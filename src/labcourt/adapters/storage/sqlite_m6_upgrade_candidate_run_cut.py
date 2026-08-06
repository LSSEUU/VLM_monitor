"""Durable construction and exact retry of one M6 candidate-run cut."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from pathlib import Path
from typing import NoReturn

from labcourt.application.m6_upgrade_candidate_run_cut import (
    build_m6_upgrade_candidate_run_cut,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m5_artifact_validation import M5ArtifactValidationReport
from labcourt.contracts.m6_regression_execution import M6UpgradeCandidateRunCutAuthority
from labcourt.contracts.references import require_reference_token
from labcourt.exceptions import ConcurrentModification
from labcourt.ports.m6_upgrade_candidate_run_cut import (
    M6UpgradeCandidateRunCutError,
    M6UpgradeCandidateRunCutFailureCode,
    M6UpgradeCandidateValidationReportProvider,
)
from labcourt.ports.m6_upgrade_execution_ledger_v3 import (
    M6UpgradeExecutionLedgerV3Error,
    M6UpgradeExecutionLedgerV3FailureCode,
)

from ._sqlite_m6_live_read_cut import is_m6_sqlite_read_session
from ._sqlite_m6_upgrade_candidate_run_cut_codec import (
    MAX_M6_UPGRADE_CANDIDATE_RUN_CUT_BYTES,
    StoredM6UpgradeCandidateRunCut,
    candidate_run_cut_documents,
    candidate_run_cut_from_row,
)
from ._sqlite_m6_upgrade_execution_ledger_v3_codec import (
    M6SQLiteUpgradeV3State,
    _load_m6_upgrade_v3_state_from_connection_unchecked,
)
from ._sqlite_read_session import SQLiteReadSession
from .sqlite_m6_upgrade_execution_ledger import SQLiteM6UpgradeExecutionLedgerRepository
from .sqlite_repository import (
    Clock,
    MigrationIntegrityError,
    RepositoryIntegrityError,
    _row_int,
)

M6UpgradeCandidateRunCutFaultInjector = Callable[[str], None]


def _error(code: M6UpgradeCandidateRunCutFailureCode) -> M6UpgradeCandidateRunCutError:
    return M6UpgradeCandidateRunCutError(code)


def _fail(code: M6UpgradeCandidateRunCutFailureCode) -> NoReturn:
    raise _error(code)


def _require_lookup(
    candidate_run_id: object,
    execution_scope_authority_id: object,
) -> tuple[str, str]:
    try:
        if not isinstance(candidate_run_id, str):
            raise TypeError
        run_id = require_reference_token(candidate_run_id, "M6 candidate run-cut run_id")
    except (TypeError, ValueError):
        _fail(M6UpgradeCandidateRunCutFailureCode.INVALID_ARGUMENT)
    if (
        not isinstance(execution_scope_authority_id, str)
        or len(execution_scope_authority_id) != 64
        or any(character not in "0123456789abcdef" for character in execution_scope_authority_id)
    ):
        _fail(M6UpgradeCandidateRunCutFailureCode.INVALID_ARGUMENT)
    return run_id, execution_scope_authority_id


def _translate_state_error(error: M6UpgradeExecutionLedgerV3Error) -> NoReturn:
    mapping = {
        M6UpgradeExecutionLedgerV3FailureCode.INVALID_ARGUMENT: (
            M6UpgradeCandidateRunCutFailureCode.INVALID_ARGUMENT
        ),
        M6UpgradeExecutionLedgerV3FailureCode.SCOPE_NOT_FOUND: (
            M6UpgradeCandidateRunCutFailureCode.SCOPE_NOT_FOUND
        ),
        M6UpgradeExecutionLedgerV3FailureCode.SCOPE_MISMATCH: (
            M6UpgradeCandidateRunCutFailureCode.SCOPE_MISMATCH
        ),
        M6UpgradeExecutionLedgerV3FailureCode.LEDGER_VERSION_UNSUPPORTED: (
            M6UpgradeCandidateRunCutFailureCode.LEDGER_VERSION_UNSUPPORTED
        ),
        M6UpgradeExecutionLedgerV3FailureCode.LEGACY_LEDGER_UNSUPPORTED: (
            M6UpgradeCandidateRunCutFailureCode.LEDGER_VERSION_UNSUPPORTED
        ),
        M6UpgradeExecutionLedgerV3FailureCode.DOCUMENT_TOO_LARGE: (
            M6UpgradeCandidateRunCutFailureCode.DOCUMENT_TOO_LARGE
        ),
        M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID: (
            M6UpgradeCandidateRunCutFailureCode.STORED_AUTHORITY_INVALID
        ),
    }
    _fail(mapping.get(error.reason_code, M6UpgradeCandidateRunCutFailureCode.SNAPSHOT_REJECTED))


def _report_size(report: M5ArtifactValidationReport) -> int:
    return len(canonical_json(report.model_dump(mode="json")).encode("utf-8"))


def _require_0015_layout(connection: SQLiteReadSession) -> None:
    installed = connection.execute(
        """
        SELECT COUNT(*) AS object_count
        FROM sqlite_master
        WHERE (type = 'table' AND name = 'm6_upgrade_candidate_run_cuts')
           OR (type = 'trigger' AND name IN (
               'm6_upgrade_candidate_run_cuts_validate',
               'm6_upgrade_candidate_run_cuts_no_replace',
               'm6_upgrade_candidate_run_cuts_no_update',
               'm6_upgrade_candidate_run_cuts_no_delete'
           ))
        """
    ).fetchone()
    if installed is None or _row_int(installed, "object_count") != 5:
        raise MigrationIntegrityError(
            "SQLite M6 candidate run-cut layout is incomplete; apply migration 0015"
        )


def _require_active_transaction(connection: SQLiteReadSession) -> None:
    if not connection.in_transaction:
        _fail(M6UpgradeCandidateRunCutFailureCode.SNAPSHOT_REJECTED)


def _stored_candidate_run_cut(
    connection: SQLiteReadSession,
    state: M6SQLiteUpgradeV3State,
) -> StoredM6UpgradeCandidateRunCut | None:
    scope = state.stored_scope.authority
    seal = state.seal
    if seal is None:
        _fail(M6UpgradeCandidateRunCutFailureCode.LEDGER_NOT_SEALED)
    preflight = connection.execute(
        """
        SELECT
            COUNT(*) AS item_count,
            COALESCE(MAX(size_bytes), 0) AS max_claimed_bytes,
            COALESCE(MAX(length(CAST(run_cut_json AS BLOB))), 0) AS max_actual_bytes,
            COALESCE(SUM(CASE
                WHEN typeof(size_bytes) <> 'integer'
                  OR typeof(run_cut_json) <> 'text'
                  OR size_bytes < 1
                  OR size_bytes <> length(CAST(run_cut_json AS BLOB))
                THEN 1 ELSE 0 END), 0) AS invalid_count
        FROM m6_upgrade_candidate_run_cuts
        WHERE run_id = ? AND execution_scope_authority_id = ?
        """,
        (scope.candidate_run_id, scope.execution_scope_authority_id),
    ).fetchone()
    if preflight is None:
        _fail(M6UpgradeCandidateRunCutFailureCode.STORED_AUTHORITY_INVALID)
    _require_active_transaction(connection)
    try:
        item_count = _row_int(preflight, "item_count")
        max_claimed = _row_int(preflight, "max_claimed_bytes")
        max_actual = _row_int(preflight, "max_actual_bytes")
        invalid_count = _row_int(preflight, "invalid_count")
    except (IndexError, KeyError, TypeError, RepositoryIntegrityError):
        _fail(M6UpgradeCandidateRunCutFailureCode.STORED_AUTHORITY_INVALID)
    if item_count > 1 or invalid_count:
        _fail(M6UpgradeCandidateRunCutFailureCode.STORED_AUTHORITY_INVALID)
    if (
        max_claimed > MAX_M6_UPGRADE_CANDIDATE_RUN_CUT_BYTES
        or max_actual > MAX_M6_UPGRADE_CANDIDATE_RUN_CUT_BYTES
    ):
        _fail(M6UpgradeCandidateRunCutFailureCode.DOCUMENT_TOO_LARGE)
    if item_count == 0:
        return None
    row = connection.execute(
        """
        SELECT * FROM m6_upgrade_candidate_run_cuts
        WHERE run_id = ? AND execution_scope_authority_id = ?
        """,
        (scope.candidate_run_id, scope.execution_scope_authority_id),
    ).fetchone()
    if row is None:
        _fail(M6UpgradeCandidateRunCutFailureCode.STORED_AUTHORITY_INVALID)
    _require_active_transaction(connection)
    try:
        return candidate_run_cut_from_row(
            row,
            execution_scope=scope,
            execution_ledger=seal,
        )
    except RepositoryIntegrityError:
        _fail(M6UpgradeCandidateRunCutFailureCode.STORED_AUTHORITY_INVALID)


def _attempt_load_m6_upgrade_candidate_run_cut_from_connection(
    *,
    connection: object,
    state: object,
) -> M6UpgradeCandidateRunCutAuthority:
    if not is_m6_sqlite_read_session(connection) or not isinstance(state, M6SQLiteUpgradeV3State):
        _fail(M6UpgradeCandidateRunCutFailureCode.INVALID_ARGUMENT)
    try:
        _require_active_transaction(connection)
        _require_0015_layout(connection)
        _require_active_transaction(connection)
        stored = _stored_candidate_run_cut(connection, state)
        _require_active_transaction(connection)
    except M6UpgradeCandidateRunCutError:
        raise
    except MigrationIntegrityError:
        _fail(M6UpgradeCandidateRunCutFailureCode.STORED_AUTHORITY_INVALID)
    except sqlite3.DatabaseError:
        _fail(M6UpgradeCandidateRunCutFailureCode.STORED_AUTHORITY_INVALID)
    except Exception:
        _fail(M6UpgradeCandidateRunCutFailureCode.SNAPSHOT_REJECTED)
    if stored is None:
        _fail(M6UpgradeCandidateRunCutFailureCode.RUN_CUT_NOT_FOUND)
    return stored.authority


def load_m6_upgrade_candidate_run_cut_from_connection(
    *,
    connection: SQLiteReadSession,
    state: M6SQLiteUpgradeV3State,
) -> M6UpgradeCandidateRunCutAuthority:
    """Load the unique durable cut through a fresh payload-free read facade."""

    failure = M6UpgradeCandidateRunCutFailureCode.SNAPSHOT_REJECTED
    try:
        return _attempt_load_m6_upgrade_candidate_run_cut_from_connection(
            connection=connection,
            state=state,
        )
    except M6UpgradeCandidateRunCutError as error:
        failure = error.reason_code
    except Exception:
        pass
    del connection, state
    raise _error(failure) from None


class SQLiteM6UpgradeCandidateRunCutRepository(SQLiteM6UpgradeExecutionLedgerRepository):
    """Build once from a sealed V3 cut; later loads never follow the current tail."""

    def __init__(
        self,
        database_path: str | Path,
        busy_timeout_ms: int,
        *,
        validation_report_provider: M6UpgradeCandidateValidationReportProvider,
        clock: Clock | None = None,
        fault_injector: M6UpgradeCandidateRunCutFaultInjector | None = None,
    ) -> None:
        if not callable(
            getattr(
                validation_report_provider,
                "load_m6_upgrade_candidate_validation_report",
                None,
            )
        ):
            raise TypeError("validation_report_provider must implement the M6 report boundary")
        super().__init__(
            database_path,
            busy_timeout_ms,
            clock=clock,
            fault_injector=fault_injector,
        )
        self._validation_report_provider = validation_report_provider

    def _connection(self) -> sqlite3.Connection:
        connection = super()._connection()
        try:
            _require_0015_layout(connection)
            return connection
        except BaseException:
            connection.close()
            raise

    def _cut_fault(self, phase: str) -> None:
        if not isinstance(phase, str) or not phase:
            raise TypeError("M6 candidate run-cut fault phase must be non-empty")
        if self._fault_injector is not None:
            self._fault_injector(f"m6_upgrade_candidate_run_cut.{phase}")

    def _load_state(
        self,
        connection: SQLiteReadSession,
        run_id: str,
        scope_id: str,
    ) -> M6SQLiteUpgradeV3State:
        try:
            return _load_m6_upgrade_v3_state_from_connection_unchecked(
                self,
                connection,
                run_id,
                scope_id,
            )
        except M6UpgradeExecutionLedgerV3Error as exc:
            _translate_state_error(exc)

    @staticmethod
    def _require_sealed(state: M6SQLiteUpgradeV3State) -> None:
        if state.seal is None:
            _fail(M6UpgradeCandidateRunCutFailureCode.LEDGER_NOT_SEALED)

    @staticmethod
    def _stored_cut(
        connection: SQLiteReadSession,
        state: M6SQLiteUpgradeV3State,
    ) -> StoredM6UpgradeCandidateRunCut | None:
        return _stored_candidate_run_cut(connection, state)

    def _load_validation_report(
        self,
        state: M6SQLiteUpgradeV3State,
    ) -> M5ArtifactValidationReport:
        seal = state.seal
        if seal is None:
            _fail(M6UpgradeCandidateRunCutFailureCode.LEDGER_NOT_SEALED)
        try:
            report = self._validation_report_provider.load_m6_upgrade_candidate_validation_report(
                seal.candidate_run_id,
                seal.source_audit_head_sequence,
                seal.source_audit_head_hash,
            )
        except Exception:
            _fail(M6UpgradeCandidateRunCutFailureCode.VALIDATION_REPORT_REJECTED)
        if type(report) is not M5ArtifactValidationReport:
            _fail(M6UpgradeCandidateRunCutFailureCode.VALIDATION_REPORT_REJECTED)
        return report

    @staticmethod
    def _build_authority(
        state: M6SQLiteUpgradeV3State,
        report: M5ArtifactValidationReport,
    ) -> M6UpgradeCandidateRunCutAuthority:
        seal = state.seal
        if seal is None:
            _fail(M6UpgradeCandidateRunCutFailureCode.LEDGER_NOT_SEALED)
        try:
            return build_m6_upgrade_candidate_run_cut(
                execution_scope=state.stored_scope.authority,
                execution_ledger=seal,
                validation_report=report,
            )
        except M6UpgradeCandidateRunCutError as exc:
            code = exc.reason_code
            if code == M6UpgradeCandidateRunCutFailureCode.INVALID_ARGUMENT:
                code = M6UpgradeCandidateRunCutFailureCode.VALIDATION_REPORT_REJECTED
            _fail(code)

    @staticmethod
    def _insert_cut(
        connection: SQLiteReadSession,
        state: M6SQLiteUpgradeV3State,
        stored: StoredM6UpgradeCandidateRunCut,
    ) -> None:
        seal = state.seal
        if seal is None:
            _fail(M6UpgradeCandidateRunCutFailureCode.LEDGER_NOT_SEALED)
        authority = stored.authority
        report = authority.validation_report
        connection.execute(
            """
            INSERT INTO m6_upgrade_candidate_run_cuts(
                run_id, execution_scope_authority_id, ledger_seal_authority_id,
                candidate_manifest_id, candidate_manifest_content_sha256,
                candidate_config_sha256, candidate_config_content_sha256,
                execution_component_manifest_id, audit_head_sequence, audit_head_hash,
                validation_report_id, validation_report_content_sha256,
                validation_report_size_bytes, candidate_run_cut_authority_id,
                run_cut_json, document_sha256, size_bytes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                authority.candidate_run_id,
                state.stored_scope.authority.execution_scope_authority_id,
                seal.ledger_seal_authority_id,
                authority.candidate_manifest.manifest_id,
                authority.candidate_manifest_content_sha256,
                authority.candidate_config.config_sha256,
                authority.candidate_config_content_sha256,
                authority.execution_component_manifest_id,
                authority.audit_head_sequence,
                authority.audit_head_hash,
                report.report_id,
                authority.validation_report_content_sha256,
                _report_size(report),
                authority.candidate_run_cut_authority_id,
                stored.document,
                stored.document_sha256,
                stored.size_bytes,
            ),
        )

    def _attempt_build_or_load(
        self,
        candidate_run_id: object,
        execution_scope_authority_id: object,
    ) -> M6UpgradeCandidateRunCutAuthority:
        run_id, scope_id = _require_lookup(candidate_run_id, execution_scope_authority_id)
        try:
            with self._read() as connection:
                initial_state = self._load_state(connection, run_id, scope_id)
                self._require_sealed(initial_state)
                existing = self._stored_cut(connection, initial_state)
                if existing is not None:
                    return existing.authority
            report = self._load_validation_report(initial_state)
            expected = self._build_authority(initial_state, report)
            expected_documents = candidate_run_cut_documents(expected)
            with self._immediate() as connection:
                state = self._load_state(connection, run_id, scope_id)
                self._require_sealed(state)
                if (
                    state.seal != initial_state.seal
                    or state.stored_scope != initial_state.stored_scope
                ):
                    _fail(M6UpgradeCandidateRunCutFailureCode.SNAPSHOT_REJECTED)
                existing = self._stored_cut(connection, state)
                if existing is not None:
                    if existing != expected_documents:
                        _fail(M6UpgradeCandidateRunCutFailureCode.RUN_CUT_CONFLICT)
                    return existing.authority
                self._insert_cut(connection, state, expected_documents)
                self._cut_fault("after_insert")
                observed = self._stored_cut(connection, state)
                if observed != expected_documents:
                    _fail(M6UpgradeCandidateRunCutFailureCode.STORED_AUTHORITY_INVALID)
                self._cut_fault("before_commit")
                return expected
        except M6UpgradeCandidateRunCutError:
            raise
        except ConcurrentModification:
            _fail(M6UpgradeCandidateRunCutFailureCode.STORAGE_REJECTED)
        except sqlite3.IntegrityError:
            _fail(M6UpgradeCandidateRunCutFailureCode.STORAGE_REJECTED)
        except sqlite3.DatabaseError:
            _fail(M6UpgradeCandidateRunCutFailureCode.STORED_AUTHORITY_INVALID)
        except RepositoryIntegrityError:
            _fail(M6UpgradeCandidateRunCutFailureCode.STORED_AUTHORITY_INVALID)

    def build_or_load(
        self,
        candidate_run_id: str,
        execution_scope_authority_id: str,
    ) -> M6UpgradeCandidateRunCutAuthority:
        """Build or load through a payload-free two-identity facade."""

        failure = M6UpgradeCandidateRunCutFailureCode.STORAGE_REJECTED
        try:
            return self._attempt_build_or_load(
                candidate_run_id,
                execution_scope_authority_id,
            )
        except M6UpgradeCandidateRunCutError as error:
            failure = error.reason_code
        except Exception:
            pass
        del self, candidate_run_id, execution_scope_authority_id
        raise _error(failure) from None


__all__ = [
    "M6UpgradeCandidateRunCutFaultInjector",
    "SQLiteM6UpgradeCandidateRunCutRepository",
    "load_m6_upgrade_candidate_run_cut_from_connection",
]
