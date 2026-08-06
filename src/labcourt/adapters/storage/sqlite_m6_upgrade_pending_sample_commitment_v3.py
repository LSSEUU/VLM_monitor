"""Protocol-V3 SQLite persistence for the unchanged pending commitment wire."""

from __future__ import annotations

import sqlite3
from typing import NoReturn

from labcourt.contracts.m6_regression import MAX_M6_REGRESSION_CASES
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6_UPGRADE_LEDGER_GENESIS_HASH,
    M6UpgradeExecutionScopeAuthority,
    M6UpgradeSampleExecutionRecordV2,
)
from labcourt.contracts.m6_upgrade_pending_sample_commitment import (
    M6UpgradePendingSampleCommitmentAuthority,
)
from labcourt.contracts.references import require_reference_token
from labcourt.exceptions import ConcurrentModification
from labcourt.ports.m6_upgrade_execution_ledger import (
    M6UpgradeExecutionLedgerError,
    M6UpgradeExecutionLedgerFailureCode,
)
from labcourt.ports.m6_upgrade_execution_ledger_v3 import (
    M6UpgradeExecutionLedgerV3Error,
    M6UpgradeExecutionLedgerV3FailureCode,
)
from labcourt.ports.m6_upgrade_pending_sample_commitment import (
    M6UpgradePendingSampleCommitmentError,
    M6UpgradePendingSampleCommitmentFailureCode,
)

from ._sqlite_m6_upgrade_execution_ledger_codec import (
    MAX_M6_UPGRADE_LEDGER_PREFIX_BYTES,
    MAX_M6_UPGRADE_RECORD_BYTES,
    M6UpgradeLedgerProtocolVersion,
    StoredM6UpgradeScope,
    _preflight_stored_inventory,
)
from ._sqlite_m6_upgrade_execution_ledger_v3_codec import (
    M6SQLiteUpgradeV3State,
    _load_m6_upgrade_v3_state_from_connection_unchecked,
    observation_v2_closes_record_v2,
    stored_scope_v3_from_connection,
)
from ._sqlite_m6_upgrade_pending_sample_commitment_codec import (
    MAX_M6_UPGRADE_PENDING_COMMITMENT_BYTES,
    MAX_M6_UPGRADE_PENDING_COMMITMENT_INVENTORY_BYTES,
    MAX_M6_UPGRADE_PENDING_RECORD_BYTES,
    MAX_M6_UPGRADE_PENDING_RECORD_INVENTORY_BYTES,
    M6UpgradePendingSampleCommitmentDocuments,
    canonical_pending_sample_commitment,
    pending_sample_commitment_documents,
)
from ._sqlite_m6_upgrade_v2_prefix import (
    validate_m6_upgrade_v2_prefix_identity_closure,
)
from ._sqlite_read_session import SQLiteReadSession
from .sqlite_m6_upgrade_execution_ledger import SQLiteM6UpgradeExecutionLedgerRepository
from .sqlite_repository import RepositoryIntegrityError


def _error(
    code: M6UpgradePendingSampleCommitmentFailureCode,
) -> M6UpgradePendingSampleCommitmentError:
    return M6UpgradePendingSampleCommitmentError(code)


def _require_lookup(
    candidate_run_id: object,
    execution_scope_authority_id: object,
    ledger_sequence: object,
) -> tuple[str, str, int]:
    try:
        if not isinstance(candidate_run_id, str):
            raise TypeError
        run_id = require_reference_token(
            candidate_run_id,
            "M6 V3 pending sample commitment candidate run_id",
        )
    except (TypeError, ValueError) as exc:
        raise _error(M6UpgradePendingSampleCommitmentFailureCode.INVALID_ARGUMENT) from exc
    if (
        not isinstance(execution_scope_authority_id, str)
        or len(execution_scope_authority_id) != 64
        or any(character not in "0123456789abcdef" for character in execution_scope_authority_id)
        or not isinstance(ledger_sequence, int)
        or isinstance(ledger_sequence, bool)
        or not 0 <= ledger_sequence < MAX_M6_REGRESSION_CASES
    ):
        raise _error(M6UpgradePendingSampleCommitmentFailureCode.INVALID_ARGUMENT)
    return run_id, execution_scope_authority_id, ledger_sequence


def _translate_base_error(error: M6UpgradeExecutionLedgerError) -> NoReturn:
    mapping = {
        M6UpgradeExecutionLedgerFailureCode.INVALID_ARGUMENT: (
            M6UpgradePendingSampleCommitmentFailureCode.INVALID_ARGUMENT
        ),
        M6UpgradeExecutionLedgerFailureCode.SCOPE_NOT_FOUND: (
            M6UpgradePendingSampleCommitmentFailureCode.SCOPE_NOT_FOUND
        ),
        M6UpgradeExecutionLedgerFailureCode.SCOPE_CONFLICT: (
            M6UpgradePendingSampleCommitmentFailureCode.SCOPE_MISMATCH
        ),
        M6UpgradeExecutionLedgerFailureCode.SCOPE_MISMATCH: (
            M6UpgradePendingSampleCommitmentFailureCode.SCOPE_MISMATCH
        ),
        M6UpgradeExecutionLedgerFailureCode.LEDGER_VERSION_UNSUPPORTED: (
            M6UpgradePendingSampleCommitmentFailureCode.LEGACY_LEDGER_UNSUPPORTED
        ),
        M6UpgradeExecutionLedgerFailureCode.DOCUMENT_TOO_LARGE: (
            M6UpgradePendingSampleCommitmentFailureCode.DOCUMENT_TOO_LARGE
        ),
        M6UpgradeExecutionLedgerFailureCode.SQLITE_REJECTED: (
            M6UpgradePendingSampleCommitmentFailureCode.STORAGE_REJECTED
        ),
    }
    translated = mapping.get(error.reason_code)
    if translated is not None:
        raise _error(translated) from error
    raise _error(M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID) from error


def _translate_v3_error(error: M6UpgradeExecutionLedgerV3Error) -> NoReturn:
    mapping = {
        M6UpgradeExecutionLedgerV3FailureCode.INVALID_ARGUMENT: (
            M6UpgradePendingSampleCommitmentFailureCode.INVALID_ARGUMENT
        ),
        M6UpgradeExecutionLedgerV3FailureCode.SCOPE_NOT_FOUND: (
            M6UpgradePendingSampleCommitmentFailureCode.SCOPE_NOT_FOUND
        ),
        M6UpgradeExecutionLedgerV3FailureCode.SCOPE_CONFLICT: (
            M6UpgradePendingSampleCommitmentFailureCode.SCOPE_MISMATCH
        ),
        M6UpgradeExecutionLedgerV3FailureCode.SCOPE_MISMATCH: (
            M6UpgradePendingSampleCommitmentFailureCode.SCOPE_MISMATCH
        ),
        M6UpgradeExecutionLedgerV3FailureCode.LEDGER_VERSION_UNSUPPORTED: (
            M6UpgradePendingSampleCommitmentFailureCode.LEGACY_LEDGER_UNSUPPORTED
        ),
        M6UpgradeExecutionLedgerV3FailureCode.LEGACY_LEDGER_UNSUPPORTED: (
            M6UpgradePendingSampleCommitmentFailureCode.LEGACY_LEDGER_UNSUPPORTED
        ),
        M6UpgradeExecutionLedgerV3FailureCode.LEDGER_SEALED: (
            M6UpgradePendingSampleCommitmentFailureCode.LEDGER_SEALED
        ),
        M6UpgradeExecutionLedgerV3FailureCode.DOCUMENT_TOO_LARGE: (
            M6UpgradePendingSampleCommitmentFailureCode.DOCUMENT_TOO_LARGE
        ),
        M6UpgradeExecutionLedgerV3FailureCode.STORAGE_REJECTED: (
            M6UpgradePendingSampleCommitmentFailureCode.STORAGE_REJECTED
        ),
    }
    translated = mapping.get(error.reason_code)
    if translated is not None:
        raise _error(translated) from error
    raise _error(M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID) from error


class SQLiteM6UpgradePendingSampleCommitmentV3Repository(SQLiteM6UpgradeExecutionLedgerRepository):
    """Persist one unchanged Pending-V1 authority inside a V3 state machine."""

    def _commitment_v3_fault(self, phase: str) -> None:
        if not isinstance(phase, str) or not phase:
            raise TypeError("M6 V3 commitment fault phase must be a non-empty string")
        if self._fault_injector is not None:
            self._fault_injector(f"m6_upgrade_pending_sample_commitment_v3.{phase}")

    def _stored_scope_for_begin(
        self,
        connection: SQLiteReadSession,
        run_id: str,
        execution_scope_authority_id: str,
    ) -> StoredM6UpgradeScope:
        return stored_scope_v3_from_connection(
            connection,
            run_id,
            execution_scope_authority_id,
        )

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
            _translate_v3_error(exc)

    def _attempt_begin_execution(
        self,
        scope: M6UpgradeExecutionScopeAuthority,
    ) -> M6UpgradeExecutionScopeAuthority:
        try:
            return self._begin_execution_with_protocol(
                scope,
                protocol_version=M6UpgradeLedgerProtocolVersion.V3,
            )
        except M6UpgradeExecutionLedgerV3Error as exc:
            _translate_v3_error(exc)
        except M6UpgradeExecutionLedgerError as exc:
            _translate_base_error(exc)

    def begin_execution(
        self,
        scope: M6UpgradeExecutionScopeAuthority,
    ) -> M6UpgradeExecutionScopeAuthority:
        """Begin V3 execution without retaining lower diagnostic chains."""

        failure = M6UpgradePendingSampleCommitmentFailureCode.STORAGE_REJECTED
        try:
            return self._attempt_begin_execution(scope)
        except M6UpgradePendingSampleCommitmentError as error:
            failure = error.reason_code
        except Exception:
            pass
        del self, scope
        raise _error(failure) from None

    @staticmethod
    def _record_is_next(
        state: M6SQLiteUpgradeV3State,
        commitment: M6UpgradePendingSampleCommitmentAuthority,
    ) -> bool:
        scope = state.stored_scope.authority
        sequence = len(state.records)
        entries = scope.execution_dataset.entries
        expected_previous = (
            state.records[-1].sample_execution_record_id
            if state.records
            else M6_UPGRADE_LEDGER_GENESIS_HASH
        )
        return (
            sequence < len(entries)
            and commitment.ledger_sequence == sequence
            and commitment.command_id == scope.command.command_id
            and commitment.execution_dataset_snapshot_id
            == scope.execution_dataset.execution_dataset_snapshot_id
            and commitment.execution_entry == entries[sequence]
            and commitment.sample_execution_record.previous_ledger_entry_hash == expected_previous
        )

    @staticmethod
    def _insert(
        connection: sqlite3.Connection,
        commitment: M6UpgradePendingSampleCommitmentAuthority,
        documents: M6UpgradePendingSampleCommitmentDocuments,
    ) -> None:
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
                documents.sample_execution_record_json,
                documents.sample_execution_record_document_sha256,
                documents.sample_execution_record_size_bytes,
                documents.commitment_json,
                documents.document_sha256,
                documents.size_bytes,
            ),
        )

    @staticmethod
    def _validate_prospective_budgets(
        connection: SQLiteReadSession,
        state: M6SQLiteUpgradeV3State,
        documents: M6UpgradePendingSampleCommitmentDocuments,
    ) -> None:
        run_id = state.stored_scope.authority.candidate_run_id
        expected_count = len(state.stored_scope.authority.execution_dataset.entries)
        try:
            record_budget = _preflight_stored_inventory(
                connection,
                table="m6_upgrade_sample_executions",
                size_column="record_size_bytes",
                json_column="record_json",
                where_sql="run_id = ?",
                where_parameters=(run_id,),
                max_items=expected_count,
                max_item_bytes=MAX_M6_UPGRADE_RECORD_BYTES,
                max_inventory_bytes=MAX_M6_UPGRADE_LEDGER_PREFIX_BYTES,
                prefix_bytes=state.stored_scope.size_bytes,
            )
            commitment_budget = _preflight_stored_inventory(
                connection,
                table="m6_upgrade_pending_sample_commitments",
                size_column="size_bytes",
                json_column="commitment_json",
                where_sql="run_id = ?",
                where_parameters=(run_id,),
                max_items=expected_count,
                max_item_bytes=MAX_M6_UPGRADE_PENDING_COMMITMENT_BYTES,
                max_inventory_bytes=MAX_M6_UPGRADE_PENDING_COMMITMENT_INVENTORY_BYTES,
            )
            commitment_record_budget = _preflight_stored_inventory(
                connection,
                table="m6_upgrade_pending_sample_commitments",
                size_column="sample_execution_record_size_bytes",
                json_column="sample_execution_record_json",
                where_sql="run_id = ?",
                where_parameters=(run_id,),
                max_items=expected_count,
                max_item_bytes=MAX_M6_UPGRADE_PENDING_RECORD_BYTES,
                max_inventory_bytes=MAX_M6_UPGRADE_PENDING_RECORD_INVENTORY_BYTES,
            )
        except M6UpgradeExecutionLedgerError as exc:
            _translate_base_error(exc)
        if (
            state.stored_scope.size_bytes
            + record_budget.canonical_bytes
            + documents.sample_execution_record_size_bytes
            > MAX_M6_UPGRADE_LEDGER_PREFIX_BYTES
            or commitment_budget.canonical_bytes + documents.size_bytes
            > MAX_M6_UPGRADE_PENDING_COMMITMENT_INVENTORY_BYTES
            or commitment_record_budget.canonical_bytes
            + documents.sample_execution_record_size_bytes
            > MAX_M6_UPGRADE_PENDING_RECORD_INVENTORY_BYTES
        ):
            raise _error(M6UpgradePendingSampleCommitmentFailureCode.DOCUMENT_TOO_LARGE)

    def _attempt_append(
        self,
        commitment: M6UpgradePendingSampleCommitmentAuthority,
    ) -> M6UpgradePendingSampleCommitmentAuthority:
        if (
            type(commitment) is not M6UpgradePendingSampleCommitmentAuthority
            or type(commitment.sample_execution_record) is not M6UpgradeSampleExecutionRecordV2
        ):
            raise _error(M6UpgradePendingSampleCommitmentFailureCode.INVALID_ARGUMENT)
        controlled = canonical_pending_sample_commitment(commitment)
        documents = pending_sample_commitment_documents(controlled)
        try:
            with self._immediate() as connection:
                state = self._load_state(
                    connection,
                    controlled.candidate_run_id,
                    controlled.execution_scope_authority_id,
                )
                collisions = connection.execute(
                    """
                    SELECT run_id, execution_scope_authority_id, ledger_sequence
                    FROM m6_upgrade_pending_sample_commitments
                    WHERE (
                        run_id = ? AND (
                            ledger_sequence = ? OR execution_entry_id = ? OR sample_id = ?
                        )
                    )
                    OR pending_sample_commitment_authority_id = ?
                    OR observation_authority_id = ?
                    OR sample_execution_record_id = ?
                    """,
                    (
                        controlled.candidate_run_id,
                        controlled.ledger_sequence,
                        controlled.execution_entry_id,
                        controlled.sample_id,
                        controlled.pending_sample_commitment_authority_id,
                        controlled.observation_authority_id,
                        controlled.sample_execution_record_id,
                    ),
                ).fetchall()
                if collisions:
                    stored = (
                        state.commitments[controlled.ledger_sequence]
                        if len(collisions) == 1
                        and controlled.ledger_sequence < len(state.commitments)
                        else None
                    )
                    if (
                        stored is not None
                        and stored.authority == controlled
                        and stored.documents == documents
                    ):
                        return stored.authority
                    raise _error(M6UpgradePendingSampleCommitmentFailureCode.COMMITMENT_CONFLICT)

                sample_count = len(state.records)
                if state.seal is not None:
                    raise _error(M6UpgradePendingSampleCommitmentFailureCode.LEDGER_SEALED)
                if len(state.commitments) > sample_count:
                    raise _error(
                        M6UpgradePendingSampleCommitmentFailureCode.PENDING_COMMITMENT_EXISTS
                    )
                if len(state.observations) == sample_count:
                    raise _error(M6UpgradePendingSampleCommitmentFailureCode.OBSERVATION_NOT_FOUND)
                if (
                    len(state.observations) != sample_count + 1
                    or len(state.commitments) != sample_count
                ):
                    raise _error(
                        M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID
                    )
                if not observation_v2_closes_record_v2(
                    state.observations[sample_count].authority,
                    controlled.sample_execution_record,
                ):
                    raise _error(M6UpgradePendingSampleCommitmentFailureCode.OBSERVATION_MISMATCH)
                if not self._record_is_next(state, controlled):
                    raise _error(
                        M6UpgradePendingSampleCommitmentFailureCode.COMMITMENT_OUT_OF_ORDER
                    )
                try:
                    validate_m6_upgrade_v2_prefix_identity_closure(
                        (*state.records, controlled.sample_execution_record)
                    )
                except ValueError as exc:
                    raise _error(
                        M6UpgradePendingSampleCommitmentFailureCode.COMMITMENT_CONFLICT
                    ) from exc
                self._validate_prospective_budgets(connection, state, documents)
                self._insert(connection, controlled, documents)
                self._commitment_v3_fault("append.after_insert")
                readback = self._load_state(
                    connection,
                    controlled.candidate_run_id,
                    controlled.execution_scope_authority_id,
                )
                if (
                    len(readback.commitments) != len(state.commitments) + 1
                    or readback.commitments[-1].authority != controlled
                    or readback.commitments[-1].documents != documents
                ):
                    raise _error(
                        M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID
                    )
                self._commitment_v3_fault("append.before_commit")
                return readback.commitments[-1].authority
        except M6UpgradePendingSampleCommitmentError:
            raise
        except RepositoryIntegrityError as exc:
            raise _error(
                M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID
            ) from exc
        except ConcurrentModification as exc:
            raise _error(M6UpgradePendingSampleCommitmentFailureCode.STORAGE_REJECTED) from exc
        except sqlite3.IntegrityError as exc:
            raise _error(M6UpgradePendingSampleCommitmentFailureCode.STORAGE_REJECTED) from exc
        except sqlite3.DatabaseError as exc:
            raise _error(M6UpgradePendingSampleCommitmentFailureCode.STORAGE_REJECTED) from exc

    def append(
        self,
        commitment: M6UpgradePendingSampleCommitmentAuthority,
    ) -> M6UpgradePendingSampleCommitmentAuthority:
        """Append Pending V1 through a fresh payload-free public error."""

        failure = M6UpgradePendingSampleCommitmentFailureCode.STORAGE_REJECTED
        try:
            return self._attempt_append(commitment)
        except M6UpgradePendingSampleCommitmentError as error:
            failure = error.reason_code
        except Exception:
            pass
        del self, commitment
        raise _error(failure) from None

    def _attempt_load(
        self,
        candidate_run_id: str,
        execution_scope_authority_id: str,
        ledger_sequence: int,
    ) -> M6UpgradePendingSampleCommitmentAuthority:
        run_id, scope_id, sequence = _require_lookup(
            candidate_run_id,
            execution_scope_authority_id,
            ledger_sequence,
        )
        try:
            with self._read() as connection:
                state = self._load_state(connection, run_id, scope_id)
                if sequence >= len(state.commitments):
                    raise _error(M6UpgradePendingSampleCommitmentFailureCode.COMMITMENT_NOT_FOUND)
                return state.commitments[sequence].authority
        except M6UpgradePendingSampleCommitmentError:
            raise
        except RepositoryIntegrityError as exc:
            raise _error(
                M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID
            ) from exc
        except sqlite3.DatabaseError as exc:
            raise _error(
                M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID
            ) from exc

    def load(
        self,
        candidate_run_id: str,
        execution_scope_authority_id: str,
        ledger_sequence: int,
    ) -> M6UpgradePendingSampleCommitmentAuthority:
        """Load Pending V1 without retaining lookup or storage payloads."""

        failure = M6UpgradePendingSampleCommitmentFailureCode.STORAGE_REJECTED
        try:
            return self._attempt_load(
                candidate_run_id,
                execution_scope_authority_id,
                ledger_sequence,
            )
        except M6UpgradePendingSampleCommitmentError as error:
            failure = error.reason_code
        except Exception:
            pass
        del self, candidate_run_id, execution_scope_authority_id, ledger_sequence
        raise _error(failure) from None


__all__ = ["SQLiteM6UpgradePendingSampleCommitmentV3Repository"]
