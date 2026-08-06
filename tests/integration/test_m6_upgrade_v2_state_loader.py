from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from labcourt.adapters.storage import sqlite_m6_upgrade_execution_ledger_v2 as v2_repository
from labcourt.adapters.storage.sqlite_m6_upgrade_execution_ledger_v2 import (
    M6SQLiteUpgradeV2State,
    SQLiteM6UpgradeExecutionLedgerV2Repository,
    load_m6_upgrade_v2_state_from_connection,
)
from labcourt.adapters.storage.sqlite_repository import MigrationRunner
from labcourt.ports.m6_upgrade_execution_ledger_v2 import (
    M6UpgradeExecutionLedgerV2Error,
    M6UpgradeExecutionLedgerV2FailureCode,
)
from tests.integration.test_m6_upgrade_execution_ledger_v2_repository import _initialize

BUSY_TIMEOUT_MS = 2_000


def _connection(database: Path, *, begin: bool) -> sqlite3.Connection:
    connection = sqlite3.connect(database, isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA trusted_schema = OFF")
    if begin:
        connection.execute("BEGIN")
    return connection


def test_loader_requires_an_active_caller_owned_transaction(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    MigrationRunner(database, BUSY_TIMEOUT_MS).apply_all()
    repository = SQLiteM6UpgradeExecutionLedgerV2Repository(database, BUSY_TIMEOUT_MS)
    connection = _connection(database, begin=False)
    try:
        with pytest.raises(M6UpgradeExecutionLedgerV2Error) as raised:
            load_m6_upgrade_v2_state_from_connection(
                repository,
                connection,
                "candidate-run",
                "a" * 64,
            )
        assert raised.value.reason_code == M6UpgradeExecutionLedgerV2FailureCode.INVALID_ARGUMENT
        assert not connection.in_transaction
    finally:
        connection.close()


def test_loader_reuses_and_preserves_the_caller_connection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    repository, _commitments, scope = _initialize(database, verifier=None)
    connection = _connection(database, begin=True)

    def reject_new_connection(*_args: object, **_kwargs: object) -> sqlite3.Connection:
        raise AssertionError("V2 state loader must not open another connection")

    monkeypatch.setattr(v2_repository.sqlite3, "connect", reject_new_connection)
    try:
        state = load_m6_upgrade_v2_state_from_connection(
            repository,
            connection,
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
        )
        assert isinstance(state, M6SQLiteUpgradeV2State)
        assert state.stored_scope.authority == scope
        assert state.records == ()
        assert state.observations == ()
        assert state.commitments == ()
        assert connection.in_transaction
    finally:
        connection.rollback()
        connection.close()


def test_loader_rejects_database_failure_without_releasing_caller_transaction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    repository, _commitments, scope = _initialize(database, verifier=None)
    connection = _connection(database, begin=True)
    secret_payload = "private database path C:/people/alice/frame.png"

    def reject_storage(
        _connection: sqlite3.Connection,
        _run_id: str,
        _scope_id: str,
    ) -> None:
        raise sqlite3.DatabaseError(secret_payload)

    monkeypatch.setattr(
        type(repository),
        "_stored_scope_v2",
        staticmethod(reject_storage),
    )
    try:
        with pytest.raises(M6UpgradeExecutionLedgerV2Error) as raised:
            load_m6_upgrade_v2_state_from_connection(
                repository,
                connection,
                scope.candidate_run_id,
                scope.execution_scope_authority_id,
            )

        assert raised.value.reason_code == M6UpgradeExecutionLedgerV2FailureCode.STORAGE_REJECTED
        assert raised.value.args == ("M6 upgrade execution ledger V2 failed: STORAGE_REJECTED",)
        assert secret_payload not in str(raised.value)
        assert secret_payload not in repr(raised.value)
        assert connection.in_transaction
        assert connection.execute("SELECT 1").fetchone()[0] == 1
    finally:
        connection.rollback()
        connection.close()
