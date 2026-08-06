from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

import pytest

import labcourt.adapters.storage.sqlite_m6_upgrade_execution_ledger as ledger_module
from labcourt.adapters.storage.sqlite_m6_upgrade_execution_ledger import (
    SQLiteM6UpgradeExecutionLedgerRepository,
)
from labcourt.contracts.audit import AuditEntry
from labcourt.contracts.enums import ArtifactKind
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6UpgradeExecutionLedgerSealV2,
    M6UpgradeExecutionScopeAuthority,
)
from labcourt.contracts.storage import ArtifactRef
from labcourt.ports.m6_upgrade_execution_ledger import (
    M6UpgradeExecutionLedgerError,
    M6UpgradeExecutionLedgerFailureCode,
    M6UpgradeExecutionLedgerStatus,
    M6UpgradeExecutionResume,
)
from tests.contract.test_m6_upgrade_observation_backed_inventory_contracts import _v2_inventory
from tests.integration.test_m6_upgrade_execution_ledger_repository import (
    _repository,
    _scope_and_no_case_records,
    _verifier,
)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _append_test_audit(
    repository: SQLiteM6UpgradeExecutionLedgerRepository,
    scope: M6UpgradeExecutionScopeAuthority,
    *,
    before_sha256: str,
    after_sha256: str,
) -> AuditEntry:
    with repository._immediate() as connection:
        head = repository._validated_head(connection, scope.candidate_run_id)
        return repository._append_audit(
            connection,
            head,
            object_ref=ArtifactRef(
                kind=ArtifactKind.CASE,
                artifact_id="d5dc6bd1-9bc7-5cc6-a9b1-ecba4cadd617",
            ),
            before_sha256=before_sha256,
            after_sha256=after_sha256,
        )


def test_sealed_resume_requires_the_exact_persisted_ledger_head(tmp_path: Path) -> None:
    scope, records = _scope_and_no_case_records()
    repository = _repository(tmp_path / "labcourt.sqlite3", scope)
    repository.begin_execution(scope)
    verifier = _verifier(records)
    for record in records:
        repository.append_sample(record, verifier)
    seal = repository.seal(scope.candidate_run_id, scope.execution_scope_authority_id)

    with pytest.raises(ValueError, match="sealed M6 resume state is inconsistent"):
        M6UpgradeExecutionResume(
            status=M6UpgradeExecutionLedgerStatus.SEALED,
            execution_scope=scope,
            committed_sample_count=len(records),
            ledger_head_hash="f" * 64,
            next_execution_entry=None,
            seal=seal,
        )


def test_v1_resume_rejects_a_v2_seal_subclass() -> None:
    seal = _v2_inventory().execution_ledger
    assert isinstance(seal, M6UpgradeExecutionLedgerSealV2)
    with pytest.raises(ValueError, match="sealed M6 resume state is inconsistent"):
        M6UpgradeExecutionResume(
            status=M6UpgradeExecutionLedgerStatus.SEALED,
            execution_scope=seal.execution_scope,
            committed_sample_count=seal.sample_execution_count,
            ledger_head_hash=seal.ledger_preseal_hash,
            next_execution_entry=None,
            seal=seal,
        )


def test_seal_keeps_a_historical_cut_but_rejects_a_missing_backing_audit_chain(
    tmp_path: Path,
) -> None:
    scope, records = _scope_and_no_case_records()
    database = tmp_path / "labcourt.sqlite3"
    repository = _repository(database, scope)
    repository.begin_execution(scope)
    verifier = _verifier(records)
    for record in records:
        repository.append_sample(record, verifier)

    first_after = _sha("first-audit-state")
    first = _append_test_audit(
        repository,
        scope,
        before_sha256=_sha("initial-audit-state"),
        after_sha256=first_after,
    )
    seal = repository.seal(scope.candidate_run_id, scope.execution_scope_authority_id)
    assert seal.source_audit_head_sequence == first.sequence
    assert seal.source_audit_head_hash == first.entry_hash

    _append_test_audit(
        repository,
        scope,
        before_sha256=first_after,
        after_sha256=_sha("second-audit-state"),
    )
    assert (
        repository.load_sealed(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        )
        == seal
    )

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.executescript(
            """
            DROP TRIGGER audit_entries_no_delete;
            CREATE TRIGGER audit_entries_no_delete
            BEFORE DELETE ON audit_entries
            BEGIN
                SELECT 1;
            END;
            """
        )
        connection.execute(
            "DELETE FROM audit_entries WHERE run_id = ? AND sequence = ?",
            (scope.candidate_run_id, first.sequence),
        )

    operations = (
        lambda: repository.load_sealed(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        ),
        lambda: repository.resume(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        ),
        lambda: repository.seal(
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        ),
        lambda: repository.append_sample(records[-1]),
    )
    for operation in operations:
        with pytest.raises(M6UpgradeExecutionLedgerError) as rejected:
            operation()
        assert (
            rejected.value.reason_code
            == M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID
        )


def test_audit_byte_budget_rejects_before_materializing_the_audit_chain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scope, _records = _scope_and_no_case_records()
    repository = _repository(tmp_path / "labcourt.sqlite3", scope)
    repository.begin_execution(scope)
    _append_test_audit(
        repository,
        scope,
        before_sha256=_sha("initial-audit-state"),
        after_sha256=_sha("oversized-audit-state"),
    )

    def must_not_materialize(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("audit chain parser must not run after byte preflight failure")

    with repository._read() as connection:
        stored_scope = repository._stored_scope(
            connection,
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        )
        monkeypatch.setattr(ledger_module, "MAX_M6_UPGRADE_SEAL_BYTES", 1)
        monkeypatch.setattr(repository, "_validated_head", must_not_materialize)
        with pytest.raises(M6UpgradeExecutionLedgerError) as rejected:
            repository._validated_run_audit_head(connection, stored_scope)
    assert rejected.value.reason_code == M6UpgradeExecutionLedgerFailureCode.DOCUMENT_TOO_LARGE
