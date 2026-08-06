from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest

from labcourt.adapters.storage._sqlite_m6_live_read_cut import (
    m6_live_committed_read_cut,
)
from labcourt.adapters.storage._sqlite_m6_upgrade_execution_ledger_v3_codec import (
    M6SQLiteUpgradeV3State,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_candidate_run_cut import (
    load_m6_upgrade_candidate_run_cut_from_connection,
)
from labcourt.adapters.storage.sqlite_m6_upgrade_execution_ledger_v3 import (
    SQLiteM6UpgradeExecutionLedgerV3Repository,
    load_m6_upgrade_v3_state_from_connection,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m6_regression_execution import M6UpgradeCandidateRunCutAuthority
from labcourt.contracts.m6_upgrade_execution_ledger import M6UpgradeExecutionScopeAuthority
from labcourt.ports.m6_upgrade_candidate_run_cut import (
    M6UpgradeCandidateRunCutError,
    M6UpgradeCandidateRunCutFailureCode,
)
from tests.integration.test_m6_upgrade_candidate_run_cut_repository import (
    BUSY_TIMEOUT_MS,
    _FixedValidationReportProvider,
    _repository,
    _sealed_runtime,
)


def _persisted_cut(
    database: Path,
) -> tuple[M6UpgradeExecutionScopeAuthority, M6UpgradeCandidateRunCutAuthority]:
    scope, _seal, report = _sealed_runtime(database)
    authority = _repository(
        database,
        _FixedValidationReportProvider(report),
    ).build_or_load(
        scope.candidate_run_id,
        scope.execution_scope_authority_id,
    )
    return scope, authority


def _load_sealed_state(
    database: Path,
    scope: M6UpgradeExecutionScopeAuthority,
) -> M6SQLiteUpgradeV3State:
    repository = SQLiteM6UpgradeExecutionLedgerV3Repository(database, BUSY_TIMEOUT_MS)
    with m6_live_committed_read_cut(database, BUSY_TIMEOUT_MS) as cut:
        with cut.selector():
            pass
        with cut.reader() as reader:
            state = load_m6_upgrade_v3_state_from_connection(
                repository,
                reader,
                scope.candidate_run_id,
                scope.execution_scope_authority_id,
            )
        with cut.writer():
            pass
    assert state.seal is not None
    return state


def _tamper_persisted_cut(database: Path, tamper: str) -> None:
    with sqlite3.connect(database) as connection:
        trigger_row = connection.execute(
            """
            SELECT sql FROM sqlite_master
            WHERE type = 'trigger'
              AND name = 'm6_upgrade_candidate_run_cuts_no_update'
            """
        ).fetchone()
        assert trigger_row is not None and isinstance(trigger_row[0], str)
        no_update_trigger_sql = trigger_row[0]
        connection.execute("DROP TRIGGER m6_upgrade_candidate_run_cuts_no_update")
        if tamper == "normalized_projection":
            connection.execute(
                """
                UPDATE m6_upgrade_candidate_run_cuts
                SET validation_report_content_sha256 = ?
                """,
                ("f" * 64,),
            )
        else:
            row = connection.execute(
                "SELECT run_cut_json FROM m6_upgrade_candidate_run_cuts"
            ).fetchone()
            assert row is not None and isinstance(row[0], str)
            payload = json.loads(row[0])
            payload["validation_report"]["authority_root_sha256"] = "e" * 64
            raw = canonical_json(payload)
            connection.execute(
                """
                UPDATE m6_upgrade_candidate_run_cuts
                SET run_cut_json = ?, document_sha256 = ?, size_bytes = ?
                """,
                (
                    raw,
                    hashlib.sha256(raw.encode("utf-8")).hexdigest(),
                    len(raw.encode("utf-8")),
                ),
            )
        connection.execute(no_update_trigger_sql)
        connection.commit()


def test_connection_loader_reads_persisted_cut_from_same_live_b_reader(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    scope, expected = _persisted_cut(database)
    repository = SQLiteM6UpgradeExecutionLedgerV3Repository(database, BUSY_TIMEOUT_MS)

    with m6_live_committed_read_cut(database, BUSY_TIMEOUT_MS) as cut:
        with cut.selector():
            pass
        with cut.reader() as reader:
            state = load_m6_upgrade_v3_state_from_connection(
                repository,
                reader,
                scope.candidate_run_id,
                scope.execution_scope_authority_id,
            )
            observed = load_m6_upgrade_candidate_run_cut_from_connection(
                connection=reader,
                state=state,
            )
            assert reader.in_transaction
        with cut.writer():
            pass

    assert state.seal is not None
    assert observed == expected


def test_connection_loader_reports_missing_durable_cut(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    scope, seal, _report = _sealed_runtime(database)
    assert seal is not None
    repository = SQLiteM6UpgradeExecutionLedgerV3Repository(database, BUSY_TIMEOUT_MS)

    with m6_live_committed_read_cut(database, BUSY_TIMEOUT_MS) as cut:
        with cut.selector():
            pass
        with cut.reader() as reader:
            state = load_m6_upgrade_v3_state_from_connection(
                repository,
                reader,
                scope.candidate_run_id,
                scope.execution_scope_authority_id,
            )
            with pytest.raises(M6UpgradeCandidateRunCutError) as raised:
                load_m6_upgrade_candidate_run_cut_from_connection(
                    connection=reader,
                    state=state,
                )
        with cut.writer():
            pass

    assert raised.value.reason_code == M6UpgradeCandidateRunCutFailureCode.RUN_CUT_NOT_FOUND


@pytest.mark.parametrize("tamper", ("canonical_body", "normalized_projection"))
def test_connection_loader_rejects_cut_body_and_projection_tampering(
    tmp_path: Path,
    tamper: str,
) -> None:
    database = tmp_path / tamper / "labcourt.sqlite3"
    database.parent.mkdir()
    scope, _expected = _persisted_cut(database)
    _tamper_persisted_cut(database, tamper)
    repository = SQLiteM6UpgradeExecutionLedgerV3Repository(database, BUSY_TIMEOUT_MS)

    with m6_live_committed_read_cut(database, BUSY_TIMEOUT_MS) as cut:
        with cut.selector():
            pass
        with cut.reader() as reader:
            state = load_m6_upgrade_v3_state_from_connection(
                repository,
                reader,
                scope.candidate_run_id,
                scope.execution_scope_authority_id,
            )
            with pytest.raises(M6UpgradeCandidateRunCutError) as raised:
                load_m6_upgrade_candidate_run_cut_from_connection(
                    connection=reader,
                    state=state,
                )
        with cut.writer():
            pass

    assert raised.value.reason_code == (
        M6UpgradeCandidateRunCutFailureCode.STORED_AUTHORITY_INVALID
    )


def test_connection_loader_rejects_connection_without_active_transaction(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    scope, _expected = _persisted_cut(database)
    state = _load_sealed_state(database, scope)

    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    try:
        assert not connection.in_transaction
        with pytest.raises(M6UpgradeCandidateRunCutError):
            load_m6_upgrade_candidate_run_cut_from_connection(
                connection=connection,
                state=state,
            )
        assert not connection.in_transaction
    finally:
        connection.close()


def test_connection_loader_rejects_cross_grafted_state_scope(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    scope, _expected = _persisted_cut(database)
    repository = SQLiteM6UpgradeExecutionLedgerV3Repository(database, BUSY_TIMEOUT_MS)

    with m6_live_committed_read_cut(database, BUSY_TIMEOUT_MS) as cut:
        with cut.selector():
            pass
        with cut.reader() as reader:
            state = load_m6_upgrade_v3_state_from_connection(
                repository,
                reader,
                scope.candidate_run_id,
                scope.execution_scope_authority_id,
            )
            cross_grafted_scope = state.stored_scope.authority.model_copy(
                update={"candidate_run_id": "run-cross-grafted"}
            )
            cross_grafted_state = replace(
                state,
                stored_scope=replace(
                    state.stored_scope,
                    authority=cross_grafted_scope,
                ),
            )
            with pytest.raises(M6UpgradeCandidateRunCutError):
                load_m6_upgrade_candidate_run_cut_from_connection(
                    connection=reader,
                    state=cross_grafted_state,
                )
        with cut.writer():
            pass
