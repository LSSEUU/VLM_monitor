from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Callable
from pathlib import Path

import pytest

from labcourt.adapters.storage import _sqlite_m6_upgrade_execution_ledger_codec as ledger_codec
from labcourt.adapters.storage._sqlite_m6_upgrade_execution_ledger_codec import (
    MAX_M6_UPGRADE_REF_BYTES,
    contract_document,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_execution_ledger import (
    SQLiteM6UpgradeExecutionLedgerRepository,
)
from labcourt.adapters.storage.sqlite_repository import (
    MigrationRunner,
    SQLiteEvidenceRepository,
)
from labcourt.contracts.m6_regression import M6ReplayExecutionOutcome
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6_UPGRADE_LEDGER_GENESIS_HASH,
    M6UpgradeExecutionScopeAuthority,
    M6UpgradeSampleArtifactLink,
    M6UpgradeSampleExecutionRecord,
)
from labcourt.contracts.m6_upgrade_physical import (
    M6UpgradeArtifactUsage,
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactRef,
)
from labcourt.ports.m6_upgrade_execution_ledger import (
    M6UpgradeExecutionLedgerError,
    M6UpgradeExecutionLedgerFailureCode,
    M6UpgradeExecutionLedgerStatus,
)
from tests.contract.test_m6_regression_execution_contracts import _inventory
from tests.contract.test_m6_upgrade_observation_backed_inventory_contracts import _v2_inventory

BUSY_TIMEOUT_MS = 2_000


class ExactSampleArtifactVerifier:
    def __init__(self, records: tuple[M6UpgradeSampleExecutionRecord, ...]) -> None:
        self._closures = {
            record.sample_execution_record_id: tuple(
                link.artifact for link in record.artifact_links
            )
            for record in records
        }
        self.calls: list[M6UpgradeSampleExecutionRecord] = []

    def verify_m6_upgrade_sample_artifacts(
        self,
        record: M6UpgradeSampleExecutionRecord,
    ) -> tuple[M6UpgradePhysicalArtifactRef, ...]:
        self.calls.append(record)
        return self._closures[record.sample_execution_record_id]


class StubSampleArtifactVerifier:
    def __init__(self, result: object) -> None:
        self._result = result
        self.calls: list[M6UpgradeSampleExecutionRecord] = []

    def verify_m6_upgrade_sample_artifacts(
        self,
        record: M6UpgradeSampleExecutionRecord,
    ) -> object:
        self.calls.append(record)
        if isinstance(self._result, Exception):
            raise self._result
        return self._result


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _scope_and_no_case_records() -> tuple[
    M6UpgradeExecutionScopeAuthority,
    tuple[M6UpgradeSampleExecutionRecord, ...],
]:
    source = _inventory().execution_ledger
    scope = source.execution_scope
    records: list[M6UpgradeSampleExecutionRecord] = []
    previous = M6_UPGRADE_LEDGER_GENESIS_HASH
    for sequence, source_record in enumerate(source.sample_executions):
        frame = next(
            link.artifact
            for link in source_record.artifact_links
            if link.artifact.kind == M6UpgradePhysicalArtifactKind.FRAME
        )
        record = M6UpgradeSampleExecutionRecord(
            execution_scope_authority_id=scope.execution_scope_authority_id,
            candidate_run_id=scope.candidate_run_id,
            command_id=scope.command.command_id,
            execution_dataset_snapshot_id=(scope.execution_dataset.execution_dataset_snapshot_id),
            execution_entry=scope.execution_dataset.entries[sequence],
            outcome=M6ReplayExecutionOutcome.NO_CASE,
            candidate_case=None,
            artifact_links=(
                M6UpgradeSampleArtifactLink(
                    ordinal=0,
                    usage=M6UpgradeArtifactUsage.CONSUMED,
                    artifact=frame,
                ),
            ),
            ledger_sequence=sequence,
            previous_ledger_entry_hash=previous,
        )
        records.append(record)
        previous = record.sample_execution_record_id
    return scope, tuple(records)


def _scope_and_shared_ref_records() -> tuple[
    M6UpgradeExecutionScopeAuthority,
    tuple[M6UpgradeSampleExecutionRecord, ...],
]:
    scope, source_records = _scope_and_no_case_records()
    shared_frame = source_records[0].artifact_links[0].artifact
    records: list[M6UpgradeSampleExecutionRecord] = []
    previous = M6_UPGRADE_LEDGER_GENESIS_HASH
    for sequence, execution_entry in enumerate(scope.execution_dataset.entries):
        record = M6UpgradeSampleExecutionRecord(
            execution_scope_authority_id=scope.execution_scope_authority_id,
            candidate_run_id=scope.candidate_run_id,
            command_id=scope.command.command_id,
            execution_dataset_snapshot_id=(scope.execution_dataset.execution_dataset_snapshot_id),
            execution_entry=execution_entry,
            outcome=M6ReplayExecutionOutcome.NO_CASE,
            candidate_case=None,
            artifact_links=(
                M6UpgradeSampleArtifactLink(
                    ordinal=0,
                    usage=M6UpgradeArtifactUsage.CONSUMED,
                    artifact=shared_frame,
                ),
            ),
            ledger_sequence=sequence,
            previous_ledger_entry_hash=previous,
        )
        records.append(record)
        previous = record.sample_execution_record_id
    return scope, tuple(records)


def _repository(
    database: Path,
    scope: M6UpgradeExecutionScopeAuthority,
    *,
    fault_injector: Callable[[str], None] | None = None,
) -> SQLiteM6UpgradeExecutionLedgerRepository:
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    SQLiteEvidenceRepository(database, BUSY_TIMEOUT_MS).register_run(
        scope.candidate_run_id,
        scope.candidate_manifest,
    )
    return SQLiteM6UpgradeExecutionLedgerRepository(
        database,
        BUSY_TIMEOUT_MS,
        fault_injector=fault_injector,
    )


def _verifier(
    records: tuple[M6UpgradeSampleExecutionRecord, ...],
) -> ExactSampleArtifactVerifier:
    return ExactSampleArtifactVerifier(records)


def _table_counts(database: Path) -> tuple[int, int, int]:
    with sqlite3.connect(database) as connection:
        return tuple(
            int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            for table in (
                "m6_upgrade_physical_artifact_refs",
                "m6_upgrade_sample_artifact_links",
                "m6_upgrade_sample_executions",
            )
        )  # type: ignore[return-value]


def test_round_trip_is_exact_idempotent_and_seal_is_database_derived(
    tmp_path: Path,
) -> None:
    scope, records = _scope_and_no_case_records()
    repository = _repository(tmp_path / "labcourt.sqlite3", scope)
    verifier = _verifier(records)

    assert repository.begin_execution(scope) == scope
    assert repository.begin_execution(scope) == scope
    with sqlite3.connect(tmp_path / "labcourt.sqlite3") as connection:
        assert connection.execute(
            "SELECT protocol_version FROM m6_upgrade_execution_ledger_protocols WHERE run_id = ?",
            (scope.candidate_run_id,),
        ).fetchone() == ("v1",)
    initial = repository.resume(scope.candidate_run_id, scope.execution_scope_authority_id)
    assert initial.status == M6UpgradeExecutionLedgerStatus.ACTIVE
    assert initial.committed_sample_count == 0
    assert initial.ledger_head_hash == M6_UPGRADE_LEDGER_GENESIS_HASH
    assert initial.next_execution_entry == scope.execution_dataset.entries[0]

    with pytest.raises(M6UpgradeExecutionLedgerError) as missing_verifier:
        repository.append_sample(records[0])
    assert (
        missing_verifier.value.reason_code == M6UpgradeExecutionLedgerFailureCode.VERIFIER_REQUIRED
    )
    assert repository.append_sample(records[0], verifier) == records[0]
    assert verifier.calls == [records[0]]
    assert repository.append_sample(records[0], verifier) == records[0]
    assert verifier.calls == [records[0]]
    assert repository.append_sample(records[0]) == records[0]
    for record in records[1:]:
        assert repository.append_sample(record, verifier) == record
    assert verifier.calls == list(records)

    ready = repository.resume(scope.candidate_run_id, scope.execution_scope_authority_id)
    assert ready.status == M6UpgradeExecutionLedgerStatus.READY_TO_SEAL
    assert ready.committed_sample_count == len(records)
    assert ready.ledger_head_hash == records[-1].sample_execution_record_id

    seal = repository.seal(scope.candidate_run_id, scope.execution_scope_authority_id)
    assert seal.execution_scope == scope
    assert seal.sample_executions == records
    assert repository.seal(scope.candidate_run_id, scope.execution_scope_authority_id) == seal
    assert (
        repository.load_sealed(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        )
        == seal
    )
    sealed = repository.resume(scope.candidate_run_id, scope.execution_scope_authority_id)
    assert sealed.status == M6UpgradeExecutionLedgerStatus.SEALED
    assert sealed.seal == seal


def test_v1_append_rejects_a_v2_record_before_verifier_or_storage(
    tmp_path: Path,
) -> None:
    record = _v2_inventory().execution_ledger.sample_executions[0]
    verifier = StubSampleArtifactVerifier(tuple(link.artifact for link in record.artifact_links))
    repository = SQLiteM6UpgradeExecutionLedgerRepository(
        tmp_path / "missing.sqlite3",
        BUSY_TIMEOUT_MS,
    )

    with pytest.raises(M6UpgradeExecutionLedgerError) as rejected:
        repository.append_sample(record, verifier)

    assert (
        rejected.value.reason_code == M6UpgradeExecutionLedgerFailureCode.LEDGER_VERSION_UNSUPPORTED
    )
    assert verifier.calls == []


@pytest.mark.parametrize(
    "fault_phase",
    (
        "append_sample.after_refs",
        "append_sample.after_links",
        "append_sample.after_sample",
        "append_sample.before_commit",
    ),
)
def test_refs_links_and_sample_roll_back_as_one_transaction_after_crash(
    tmp_path: Path,
    fault_phase: str,
) -> None:
    scope, records = _scope_and_no_case_records()

    def fail_during_append(phase: str) -> None:
        if phase == f"m6_upgrade_execution_ledger.{fault_phase}":
            raise RuntimeError("simulated process crash")

    database = tmp_path / "labcourt.sqlite3"
    repository = _repository(database, scope, fault_injector=fail_during_append)
    repository.begin_execution(scope)

    with pytest.raises(RuntimeError, match="simulated process crash"):
        repository.append_sample(records[0], _verifier(records))

    assert _table_counts(database) == (0, 0, 0)
    recovered = SQLiteM6UpgradeExecutionLedgerRepository(database, BUSY_TIMEOUT_MS).resume(
        scope.candidate_run_id,
        scope.execution_scope_authority_id,
    )
    assert recovered.status == M6UpgradeExecutionLedgerStatus.ACTIVE
    assert recovered.committed_sample_count == 0


def test_database_rejects_links_after_sample_and_repository_rejects_after_seal(
    tmp_path: Path,
) -> None:
    scope, records = _scope_and_no_case_records()
    database = tmp_path / "labcourt.sqlite3"
    repository = _repository(database, scope)
    verifier = _verifier(records)
    repository.begin_execution(scope)
    repository.append_sample(records[0], verifier)

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        with pytest.raises(sqlite3.IntegrityError, match="invalid M6 upgrade sample artifact link"):
            connection.execute(
                """
                INSERT INTO m6_upgrade_sample_artifact_links(
                    run_id, execution_entry_id, ordinal, usage,
                    artifact_ref_id, artifact_link_id,
                    link_json, link_document_sha256, link_size_bytes
                )
                SELECT run_id, execution_entry_id, ordinal + 1, usage,
                       artifact_ref_id, artifact_link_id,
                       link_json, link_document_sha256, link_size_bytes
                FROM m6_upgrade_sample_artifact_links
                WHERE run_id = ? AND execution_entry_id = ? AND ordinal = 0
                """,
                (scope.candidate_run_id, records[0].execution_entry_id),
            )

    for record in records[1:]:
        repository.append_sample(record, verifier)
    repository.seal(scope.candidate_run_id, scope.execution_scope_authority_id)

    with pytest.raises(M6UpgradeExecutionLedgerError) as sealed_append:
        repository.append_sample(records[0], verifier)
    assert sealed_append.value.reason_code == M6UpgradeExecutionLedgerFailureCode.LEDGER_SEALED


def test_caller_forged_physical_ref_is_rejected_before_any_write(tmp_path: Path) -> None:
    scope, records = _scope_and_no_case_records()
    database = tmp_path / "labcourt.sqlite3"
    repository = _repository(database, scope)
    repository.begin_execution(scope)
    original = records[0].artifact_links[0].artifact
    forged = original.model_copy(update={"content_sha256": _sha("forged-content")})
    forged_record = M6UpgradeSampleExecutionRecord(
        execution_scope_authority_id=scope.execution_scope_authority_id,
        candidate_run_id=scope.candidate_run_id,
        command_id=scope.command.command_id,
        execution_dataset_snapshot_id=scope.execution_dataset.execution_dataset_snapshot_id,
        execution_entry=scope.execution_dataset.entries[0],
        outcome=M6ReplayExecutionOutcome.NO_CASE,
        candidate_case=None,
        artifact_links=(
            M6UpgradeSampleArtifactLink(
                ordinal=0,
                usage=M6UpgradeArtifactUsage.CONSUMED,
                artifact=forged,
            ),
        ),
        ledger_sequence=0,
        previous_ledger_entry_hash=M6_UPGRADE_LEDGER_GENESIS_HASH,
    )
    verifier = _verifier(records)

    with pytest.raises(M6UpgradeExecutionLedgerError) as rejected:
        repository.append_sample(forged_record, verifier)
    assert (
        rejected.value.reason_code == M6UpgradeExecutionLedgerFailureCode.PHYSICAL_ARTIFACT_REJECTED
    )
    assert verifier.calls == [forged_record]
    assert _table_counts(database) == (0, 0, 0)


@pytest.mark.parametrize(
    "result_mode",
    ("reversed", "missing", "non-tuple", "non-canonical", "exception"),
)
def test_sample_verifier_rejects_invalid_closure_with_one_call_and_zero_writes(
    tmp_path: Path,
    result_mode: str,
) -> None:
    ledger = _inventory().execution_ledger
    scope = ledger.execution_scope
    record = ledger.sample_executions[0]
    expected = tuple(link.artifact for link in record.artifact_links)
    if result_mode == "reversed":
        result: object = tuple(reversed(expected))
    elif result_mode == "missing":
        result = expected[:-1]
    elif result_mode == "non-tuple":
        result = list(expected)
    elif result_mode == "non-canonical":
        forged = expected[0].model_copy(update={"content_sha256": _sha("non-canonical")})
        result = (forged, *expected[1:])
    else:
        result = RuntimeError("sample verifier failed")
    verifier = StubSampleArtifactVerifier(result)
    database = tmp_path / "labcourt.sqlite3"
    repository = _repository(database, scope)
    repository.begin_execution(scope)

    with pytest.raises(M6UpgradeExecutionLedgerError) as rejected:
        repository.append_sample(record, verifier)  # type: ignore[arg-type]

    assert (
        rejected.value.reason_code == M6UpgradeExecutionLedgerFailureCode.PHYSICAL_ARTIFACT_REJECTED
    )
    assert verifier.calls == [record]
    assert _table_counts(database) == (0, 0, 0)


def test_record_aware_verifier_rejects_artifacts_from_another_sample_as_mixed_closure(
    tmp_path: Path,
) -> None:
    ledger = _inventory().execution_ledger
    scope = ledger.execution_scope
    first = ledger.sample_executions[0]
    second = next(item for item in ledger.sample_executions if item.candidate_case is not None)
    payload = first.model_dump(mode="python", exclude_computed_fields=True)
    payload["artifact_links"] = tuple(
        item.model_copy(update={"ordinal": ordinal})
        for ordinal, item in enumerate(
            link
            for link in second.artifact_links
            if link.artifact.kind
            in {
                M6UpgradePhysicalArtifactKind.FRAME,
                M6UpgradePhysicalArtifactKind.DETECTION,
            }
        )
    )
    mixed = M6UpgradeSampleExecutionRecord.model_validate(payload)
    verifier = ExactSampleArtifactVerifier(ledger.sample_executions)
    trusted_physical_keys = {
        link.artifact.physical_key
        for record in ledger.sample_executions
        for link in record.artifact_links
    }
    assert all(link.artifact.physical_key in trusted_physical_keys for link in mixed.artifact_links)
    database = tmp_path / "labcourt.sqlite3"
    repository = _repository(database, scope)
    repository.begin_execution(scope)

    with pytest.raises(M6UpgradeExecutionLedgerError) as rejected:
        repository.append_sample(mixed, verifier)

    assert (
        rejected.value.reason_code == M6UpgradeExecutionLedgerFailureCode.PHYSICAL_ARTIFACT_REJECTED
    )
    assert verifier.calls == [mixed]
    assert _table_counts(database) == (0, 0, 0)


@pytest.mark.parametrize(
    ("precondition", "expected_failure"),
    (
        ("out-of-order", M6UpgradeExecutionLedgerFailureCode.SAMPLE_OUT_OF_ORDER),
        ("scope-mismatch", M6UpgradeExecutionLedgerFailureCode.SCOPE_MISMATCH),
    ),
)
def test_append_rejects_preconditions_before_calling_sample_verifier(
    tmp_path: Path,
    precondition: str,
    expected_failure: M6UpgradeExecutionLedgerFailureCode,
) -> None:
    scope, records = _scope_and_no_case_records()
    if precondition == "out-of-order":
        attempted = records[1]
    else:
        payload = records[0].model_dump(mode="python", exclude_computed_fields=True)
        payload["execution_scope_authority_id"] = _sha("different-execution-scope")
        attempted = M6UpgradeSampleExecutionRecord.model_validate(payload)
    verifier = _verifier(records)
    database = tmp_path / "labcourt.sqlite3"
    repository = _repository(database, scope)
    repository.begin_execution(scope)

    with pytest.raises(M6UpgradeExecutionLedgerError) as rejected:
        repository.append_sample(attempted, verifier)

    assert rejected.value.reason_code == expected_failure
    assert verifier.calls == []
    assert _table_counts(database) == (0, 0, 0)


def test_append_rejects_missing_sample_verifier_method_before_any_write(tmp_path: Path) -> None:
    scope, records = _scope_and_no_case_records()
    database = tmp_path / "labcourt.sqlite3"
    repository = _repository(database, scope)
    repository.begin_execution(scope)

    with pytest.raises(M6UpgradeExecutionLedgerError) as rejected:
        repository.append_sample(records[0], object())  # type: ignore[arg-type]

    assert rejected.value.reason_code == M6UpgradeExecutionLedgerFailureCode.VERIFIER_INVALID
    assert _table_counts(database) == (0, 0, 0)


def test_append_rejects_a_corrupt_persisted_prefix_before_fast_retry_or_new_write(
    tmp_path: Path,
) -> None:
    scope, records = _scope_and_no_case_records()
    database = tmp_path / "labcourt.sqlite3"
    repository = _repository(database, scope)
    repository.begin_execution(scope)
    repository.append_sample(records[0], _verifier(records))

    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            DROP TRIGGER m6_upgrade_sample_executions_no_update;
            CREATE TRIGGER m6_upgrade_sample_executions_no_update
            BEFORE UPDATE ON m6_upgrade_sample_executions
            BEGIN
                SELECT 1;
            END;
            """
        )
        connection.execute(
            """
            UPDATE m6_upgrade_sample_executions
            SET record_json = '{}'
            WHERE run_id = ? AND ledger_sequence = 0
            """,
            (scope.candidate_run_id,),
        )

    verifier = _verifier(records)
    for attempted in (records[0], records[1]):
        with pytest.raises(M6UpgradeExecutionLedgerError) as rejected:
            repository.append_sample(attempted, verifier)
        assert (
            rejected.value.reason_code
            == M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID
        )
    assert verifier.calls == []
    assert _table_counts(database) == (1, 1, 1)


def test_resume_retry_and_seal_reject_an_unlinked_physical_ref(tmp_path: Path) -> None:
    scope, records = _scope_and_no_case_records()
    database = tmp_path / "labcourt.sqlite3"
    repository = _repository(database, scope)
    verifier = _verifier(records)
    repository.begin_execution(scope)
    for record in records:
        repository.append_sample(record, verifier)

    original = records[0].artifact_links[0].artifact
    orphan = original.model_copy(update={"artifact_id": "camera-orphan:stream:9"})
    ref_json, ref_sha256, ref_size = contract_document(
        orphan,
        max_bytes=MAX_M6_UPGRADE_REF_BYTES,
    )
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            """
            INSERT INTO m6_upgrade_physical_artifact_refs(
                run_id, execution_scope_authority_id,
                artifact_ref_id, source, kind, artifact_id, container_id,
                artifact_document_sha256, artifact_content_sha256,
                artifact_size_bytes, ref_json, ref_document_sha256, ref_size_bytes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scope.candidate_run_id,
                scope.execution_scope_authority_id,
                orphan.artifact_ref_id,
                orphan.source.value,
                orphan.kind.value,
                orphan.artifact_id,
                orphan.container_id,
                orphan.document_sha256,
                orphan.content_sha256,
                orphan.size_bytes,
                ref_json,
                ref_sha256,
                ref_size,
            ),
        )

    operations = (
        lambda: repository.resume(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        ),
        lambda: repository.append_sample(records[-1]),
        lambda: repository.seal(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        ),
    )
    for operation in operations:
        with pytest.raises(M6UpgradeExecutionLedgerError) as rejected:
            operation()
        assert (
            rejected.value.reason_code
            == M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID
        )


@pytest.mark.parametrize("corruption", ("wrong-scope", "missing-ref"))
def test_resume_rejects_broken_linked_ref_closure(
    tmp_path: Path,
    corruption: str,
) -> None:
    scope, records = _scope_and_no_case_records()
    database = tmp_path / "labcourt.sqlite3"
    repository = _repository(database, scope)
    repository.begin_execution(scope)
    repository.append_sample(records[0], _verifier(records))

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = OFF")
        if corruption == "wrong-scope":
            connection.executescript(
                """
                DROP TRIGGER m6_upgrade_physical_artifact_refs_no_update;
                CREATE TRIGGER m6_upgrade_physical_artifact_refs_no_update
                BEFORE UPDATE ON m6_upgrade_physical_artifact_refs
                BEGIN
                    SELECT 1;
                END;
                """
            )
            connection.execute(
                """
                UPDATE m6_upgrade_physical_artifact_refs
                SET execution_scope_authority_id = ?
                WHERE run_id = ?
                """,
                (_sha("different-scope"), scope.candidate_run_id),
            )
        else:
            connection.executescript(
                """
                DROP TRIGGER m6_upgrade_physical_artifact_refs_no_delete;
                CREATE TRIGGER m6_upgrade_physical_artifact_refs_no_delete
                BEFORE DELETE ON m6_upgrade_physical_artifact_refs
                BEGIN
                    SELECT 1;
                END;
                """
            )
            connection.execute(
                "DELETE FROM m6_upgrade_physical_artifact_refs WHERE run_id = ?",
                (scope.candidate_run_id,),
            )

    with pytest.raises(M6UpgradeExecutionLedgerError) as rejected:
        repository.resume(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        )
    assert (
        rejected.value.reason_code == M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID
    )


@pytest.mark.parametrize(
    ("budget_name", "size_query", "includes_scope"),
    (
        (
            "MAX_M6_UPGRADE_LEDGER_PREFIX_BYTES",
            "SELECT COALESCE(SUM(record_size_bytes), 0) "
            "FROM m6_upgrade_sample_executions WHERE run_id = ?",
            True,
        ),
        (
            "MAX_M6_UPGRADE_LINK_INVENTORY_BYTES",
            "SELECT COALESCE(SUM(link_size_bytes), 0) "
            "FROM m6_upgrade_sample_artifact_links WHERE run_id = ?",
            False,
        ),
        (
            "MAX_M6_UPGRADE_REF_INVENTORY_BYTES",
            "SELECT COALESCE(SUM(ref_size_bytes), 0) "
            "FROM m6_upgrade_physical_artifact_refs WHERE run_id = ?",
            False,
        ),
    ),
)
def test_resume_rejects_inventory_budget_before_parsing_raw_documents(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    budget_name: str,
    size_query: str,
    includes_scope: bool,
) -> None:
    scope, records = _scope_and_no_case_records()
    database = tmp_path / "labcourt.sqlite3"
    repository = _repository(database, scope)
    repository.begin_execution(scope)
    repository.append_sample(records[0], _verifier(records))

    with sqlite3.connect(database) as connection:
        inventory_bytes = int(
            connection.execute(size_query, (scope.candidate_run_id,)).fetchone()[0]
        )
        if includes_scope:
            inventory_bytes += int(
                connection.execute(
                    "SELECT size_bytes FROM m6_upgrade_execution_scopes WHERE run_id = ?",
                    (scope.candidate_run_id,),
                ).fetchone()[0]
            )
    assert inventory_bytes > 1
    monkeypatch.setattr(ledger_codec, budget_name, inventory_bytes - 1)

    def fail_if_raw_parser_is_reached(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("raw parser was reached before the aggregate byte gate")

    monkeypatch.setattr(ledger_codec, "_record_from_row", fail_if_raw_parser_is_reached)
    monkeypatch.setattr(ledger_codec, "_link_from_joined_row", fail_if_raw_parser_is_reached)

    with pytest.raises(M6UpgradeExecutionLedgerError) as rejected:
        repository.resume(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        )
    assert rejected.value.reason_code == M6UpgradeExecutionLedgerFailureCode.DOCUMENT_TOO_LARGE


@pytest.mark.parametrize(
    ("table", "size_column"),
    (
        ("m6_upgrade_sample_executions", "record_size_bytes"),
        ("m6_upgrade_sample_artifact_links", "link_size_bytes"),
        ("m6_upgrade_physical_artifact_refs", "ref_size_bytes"),
    ),
)
def test_resume_rejects_declared_and_sqlite_byte_length_mismatch_before_parsing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    table: str,
    size_column: str,
) -> None:
    scope, records = _scope_and_no_case_records()
    database = tmp_path / "labcourt.sqlite3"
    repository = _repository(database, scope)
    repository.begin_execution(scope)
    repository.append_sample(records[0], _verifier(records))

    no_update_trigger = f"{table}_no_update"
    with sqlite3.connect(database) as connection:
        connection.executescript(
            f"""
            DROP TRIGGER {no_update_trigger};
            CREATE TRIGGER {no_update_trigger}
            BEFORE UPDATE ON {table}
            BEGIN
                SELECT 1;
            END;
            """
        )
        connection.execute(
            f"UPDATE {table} SET {size_column} = {size_column} - 1 WHERE run_id = ?",
            (scope.candidate_run_id,),
        )

    def fail_if_raw_parser_is_reached(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("raw parser was reached before the SQLite byte-length gate")

    monkeypatch.setattr(ledger_codec, "_record_from_row", fail_if_raw_parser_is_reached)
    monkeypatch.setattr(ledger_codec, "_link_from_joined_row", fail_if_raw_parser_is_reached)

    with pytest.raises(M6UpgradeExecutionLedgerError) as rejected:
        repository.resume(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        )
    assert (
        rejected.value.reason_code == M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID
    )


def test_shared_physical_ref_is_counted_once_and_remains_sealable(tmp_path: Path) -> None:
    scope, records = _scope_and_shared_ref_records()
    database = tmp_path / "labcourt.sqlite3"
    repository = _repository(database, scope)
    repository.begin_execution(scope)
    verifier = _verifier(records)

    for record in records:
        repository.append_sample(record, verifier)

    assert _table_counts(database) == (1, len(records), len(records))
    resumed = repository.resume(
        scope.candidate_run_id,
        scope.execution_scope_authority_id,
    )
    assert resumed.status == M6UpgradeExecutionLedgerStatus.READY_TO_SEAL
    seal = repository.seal(
        scope.candidate_run_id,
        scope.execution_scope_authority_id,
    )
    assert seal.sample_executions == records
