"""Append-only SQLite persistence for trusted pre-ledger M6 observations."""

from __future__ import annotations

import sqlite3
from typing import NoReturn

from labcourt.contracts.m6_upgrade_execution_ledger import M6UpgradeExecutionScopeAuthority
from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeSampleExecutionObservationAuthority,
)
from labcourt.contracts.references import require_reference_token
from labcourt.exceptions import ConcurrentModification
from labcourt.ports.m6_upgrade_execution_ledger import (
    M6UpgradeExecutionLedgerError,
    M6UpgradeExecutionLedgerFailureCode,
)
from labcourt.ports.m6_upgrade_execution_observation import (
    M6UpgradeExecutionObservationError,
    M6UpgradeExecutionObservationFailureCode,
)
from labcourt.ports.m6_upgrade_pending_sample_commitment import (
    M6UpgradePendingSampleCommitmentError,
    M6UpgradePendingSampleCommitmentFailureCode,
)

from ._sqlite_m6_upgrade_execution_ledger_codec import (
    MAX_M6_UPGRADE_SCOPE_BYTES,
    M6UpgradeLedgerProtocolVersion,
    StoredM6UpgradeScope,
    _preflight_stored_inventory,
    ledger_protocol_from_connection,
    scope_from_row,
)
from ._sqlite_m6_upgrade_execution_observation_codec import (
    MAX_M6_UPGRADE_OBSERVATION_INVENTORY_BYTES,
    canonical_observation,
    observation_document,
    observation_from_connection,
)
from .sqlite_m6_upgrade_execution_ledger import (
    SQLiteM6UpgradeExecutionLedgerRepository,
)
from .sqlite_m6_upgrade_pending_sample_commitment import (
    SQLiteM6UpgradePendingSampleCommitmentRepository,
)
from .sqlite_repository import RepositoryIntegrityError, _row_int, _row_str


def _error(
    code: M6UpgradeExecutionObservationFailureCode,
) -> M6UpgradeExecutionObservationError:
    return M6UpgradeExecutionObservationError(code)


def _require_lookup(
    candidate_run_id: object,
    execution_scope_authority_id: object,
    ledger_sequence: object,
) -> tuple[str, str, int]:
    try:
        if not isinstance(candidate_run_id, str):
            raise TypeError
        run_id = require_reference_token(candidate_run_id, "M6 observation candidate run_id")
    except (TypeError, ValueError) as exc:
        raise _error(M6UpgradeExecutionObservationFailureCode.INVALID_ARGUMENT) from exc
    if (
        not isinstance(execution_scope_authority_id, str)
        or len(execution_scope_authority_id) != 64
        or any(character not in "0123456789abcdef" for character in execution_scope_authority_id)
        or not isinstance(ledger_sequence, int)
        or isinstance(ledger_sequence, bool)
        or ledger_sequence < 0
    ):
        raise _error(M6UpgradeExecutionObservationFailureCode.INVALID_ARGUMENT)
    return run_id, execution_scope_authority_id, ledger_sequence


def _translate_ledger_error(error: M6UpgradeExecutionLedgerError) -> NoReturn:
    mapping = {
        M6UpgradeExecutionLedgerFailureCode.INVALID_ARGUMENT: (
            M6UpgradeExecutionObservationFailureCode.INVALID_ARGUMENT
        ),
        M6UpgradeExecutionLedgerFailureCode.SCOPE_NOT_FOUND: (
            M6UpgradeExecutionObservationFailureCode.SCOPE_NOT_FOUND
        ),
        M6UpgradeExecutionLedgerFailureCode.SCOPE_CONFLICT: (
            M6UpgradeExecutionObservationFailureCode.SCOPE_MISMATCH
        ),
        M6UpgradeExecutionLedgerFailureCode.SCOPE_MISMATCH: (
            M6UpgradeExecutionObservationFailureCode.SCOPE_MISMATCH
        ),
        M6UpgradeExecutionLedgerFailureCode.LEDGER_VERSION_UNSUPPORTED: (
            M6UpgradeExecutionObservationFailureCode.LEGACY_LEDGER_UNSUPPORTED
        ),
        M6UpgradeExecutionLedgerFailureCode.LEDGER_SEALED: (
            M6UpgradeExecutionObservationFailureCode.LEDGER_SEALED
        ),
        M6UpgradeExecutionLedgerFailureCode.DOCUMENT_TOO_LARGE: (
            M6UpgradeExecutionObservationFailureCode.DOCUMENT_TOO_LARGE
        ),
        M6UpgradeExecutionLedgerFailureCode.SQLITE_REJECTED: (
            M6UpgradeExecutionObservationFailureCode.STORAGE_REJECTED
        ),
    }
    translated = mapping.get(error.reason_code)
    if translated is not None:
        raise _error(translated) from error
    raise _error(M6UpgradeExecutionObservationFailureCode.STORED_AUTHORITY_INVALID) from error


def _translate_commitment_error(error: M6UpgradePendingSampleCommitmentError) -> NoReturn:
    mapping = {
        M6UpgradePendingSampleCommitmentFailureCode.INVALID_ARGUMENT: (
            M6UpgradeExecutionObservationFailureCode.INVALID_ARGUMENT
        ),
        M6UpgradePendingSampleCommitmentFailureCode.SCOPE_NOT_FOUND: (
            M6UpgradeExecutionObservationFailureCode.SCOPE_NOT_FOUND
        ),
        M6UpgradePendingSampleCommitmentFailureCode.SCOPE_MISMATCH: (
            M6UpgradeExecutionObservationFailureCode.SCOPE_MISMATCH
        ),
        M6UpgradePendingSampleCommitmentFailureCode.LEGACY_LEDGER_UNSUPPORTED: (
            M6UpgradeExecutionObservationFailureCode.LEGACY_LEDGER_UNSUPPORTED
        ),
        M6UpgradePendingSampleCommitmentFailureCode.LEDGER_SEALED: (
            M6UpgradeExecutionObservationFailureCode.LEDGER_SEALED
        ),
        M6UpgradePendingSampleCommitmentFailureCode.DOCUMENT_TOO_LARGE: (
            M6UpgradeExecutionObservationFailureCode.DOCUMENT_TOO_LARGE
        ),
        M6UpgradePendingSampleCommitmentFailureCode.STORAGE_REJECTED: (
            M6UpgradeExecutionObservationFailureCode.STORAGE_REJECTED
        ),
    }
    translated = mapping.get(error.reason_code)
    if translated is not None:
        raise _error(translated) from error
    raise _error(M6UpgradeExecutionObservationFailureCode.STORED_AUTHORITY_INVALID) from error


class SQLiteM6UpgradeExecutionObservationRepository(SQLiteM6UpgradeExecutionLedgerRepository):
    """Persist one complete observation before its corresponding ledger row."""

    def _observation_fault(self, phase: str) -> None:
        if not isinstance(phase, str) or not phase:
            raise TypeError("M6 observation fault phase must be a non-empty string")
        if self._fault_injector is not None:
            self._fault_injector(f"m6_upgrade_execution_observation.{phase}")

    @staticmethod
    def _scope(
        connection: sqlite3.Connection,
        run_id: str,
    ) -> StoredM6UpgradeScope:
        protocol = ledger_protocol_from_connection(connection, run_id)
        if protocol is None:
            raise _error(M6UpgradeExecutionObservationFailureCode.SCOPE_NOT_FOUND)
        if protocol.version != M6UpgradeLedgerProtocolVersion.V2:
            raise _error(M6UpgradeExecutionObservationFailureCode.LEGACY_LEDGER_UNSUPPORTED)
        try:
            budget = _preflight_stored_inventory(
                connection,
                table="m6_upgrade_execution_scopes",
                size_column="size_bytes",
                json_column="scope_json",
                where_sql="run_id = ?",
                where_parameters=(run_id,),
                max_items=1,
                max_item_bytes=MAX_M6_UPGRADE_SCOPE_BYTES,
                max_inventory_bytes=MAX_M6_UPGRADE_SCOPE_BYTES,
            )
        except M6UpgradeExecutionLedgerError as exc:
            _translate_ledger_error(exc)
        if budget.item_count != 1:
            raise _error(M6UpgradeExecutionObservationFailureCode.STORED_AUTHORITY_INVALID)
        row = connection.execute(
            "SELECT * FROM m6_upgrade_execution_scopes WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        if row is None:
            raise _error(M6UpgradeExecutionObservationFailureCode.STORED_AUTHORITY_INVALID)
        try:
            stored = scope_from_row(row)
            if (
                stored.authority.execution_scope_authority_id
                != protocol.execution_scope_authority_id
            ):
                raise _error(M6UpgradeExecutionObservationFailureCode.STORED_AUTHORITY_INVALID)
            return stored
        except M6UpgradeExecutionLedgerError as exc:
            _translate_ledger_error(exc)

    def begin_execution(
        self,
        scope: M6UpgradeExecutionScopeAuthority,
    ) -> M6UpgradeExecutionScopeAuthority:
        try:
            return self._begin_execution_with_protocol(
                scope,
                protocol_version=M6UpgradeLedgerProtocolVersion.V2,
            )
        except M6UpgradeExecutionLedgerError as exc:
            _translate_ledger_error(exc)

    @staticmethod
    def _insert_artifacts(
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
                    item.source.value,
                    item.kind.value,
                    item.artifact_id,
                    item.usage.value,
                )
                for ordinal, item in enumerate(observation.artifacts)
            ),
        )

    @staticmethod
    def _insert_model_calls(
        connection: sqlite3.Connection,
        observation: M6UpgradeSampleExecutionObservationAuthority,
    ) -> None:
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
                    item.request_id,
                    item.layer.value,
                    item.role.value,
                    item.attempt_index,
                    item.result_kind.value,
                    int(item.provider_invoked),
                )
                for ordinal, item in enumerate(observation.model_calls)
            ),
        )

    @staticmethod
    def _insert_parent(
        connection: sqlite3.Connection,
        observation: M6UpgradeSampleExecutionObservationAuthority,
        raw: str,
        document_sha256: str,
        size_bytes: int,
    ) -> None:
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
                raw,
                document_sha256,
                size_bytes,
            ),
        )

    def append(
        self,
        observation: M6UpgradeSampleExecutionObservationAuthority,
    ) -> M6UpgradeSampleExecutionObservationAuthority:
        controlled = canonical_observation(observation)
        raw, document_sha256, size_bytes = observation_document(controlled)
        try:
            with self._immediate() as connection:
                stored_scope = self._scope(connection, controlled.candidate_run_id)
                scope = stored_scope.authority
                if scope.execution_scope_authority_id != (controlled.execution_scope_authority_id):
                    raise _error(M6UpgradeExecutionObservationFailureCode.SCOPE_MISMATCH)
                if (
                    connection.execute(
                        "SELECT 1 FROM m6_upgrade_execution_ledger_seals WHERE run_id = ?",
                        (controlled.candidate_run_id,),
                    ).fetchone()
                    is not None
                ):
                    raise _error(M6UpgradeExecutionObservationFailureCode.LEDGER_SEALED)

                try:
                    state = SQLiteM6UpgradePendingSampleCommitmentRepository._stored_state(
                        connection,
                        stored_scope,
                    )
                except M6UpgradePendingSampleCommitmentError as exc:
                    _translate_commitment_error(exc)

                collisions = connection.execute(
                    """
                    SELECT ledger_sequence, observation_authority_id
                    FROM m6_upgrade_sample_execution_observations
                    WHERE run_id = ? AND (
                        ledger_sequence = ? OR observation_authority_id = ?
                        OR execution_entry_id = ? OR sample_id = ?
                    )
                    """,
                    (
                        controlled.candidate_run_id,
                        controlled.ledger_sequence,
                        controlled.observation_authority_id,
                        controlled.execution_entry.execution_entry_id,
                        controlled.execution_entry.sample_id,
                    ),
                ).fetchall()
                if collisions:
                    if (
                        len(collisions) == 1
                        and _row_int(collisions[0], "ledger_sequence") == controlled.ledger_sequence
                        and _row_str(collisions[0], "observation_authority_id")
                        == controlled.observation_authority_id
                        and state.observation_count == state.sample_count + 1
                        and state.commitment_count == state.sample_count
                    ):
                        stored_retry = state.observations[-1]
                        if (
                            stored_retry.authority == controlled
                            and stored_retry.document_sha256 == document_sha256
                            and stored_retry.size_bytes == size_bytes
                        ):
                            return stored_retry.authority
                    raise _error(M6UpgradeExecutionObservationFailureCode.OBSERVATION_CONFLICT)

                if state.observation_count > state.sample_count:
                    raise _error(
                        M6UpgradeExecutionObservationFailureCode.PENDING_OBSERVATION_EXISTS
                    )
                if (
                    state.observation_bytes + size_bytes
                    > MAX_M6_UPGRADE_OBSERVATION_INVENTORY_BYTES
                ):
                    raise _error(M6UpgradeExecutionObservationFailureCode.DOCUMENT_TOO_LARGE)
                records = state.records
                entries = scope.execution_dataset.entries
                if (
                    controlled.command_id != scope.command.command_id
                    or controlled.execution_dataset_snapshot_id
                    != scope.execution_dataset.execution_dataset_snapshot_id
                    or controlled.ledger_sequence != len(records)
                    or len(records) >= len(entries)
                    or controlled.execution_entry != entries[len(records)]
                ):
                    raise _error(M6UpgradeExecutionObservationFailureCode.OBSERVATION_OUT_OF_ORDER)

                self._insert_artifacts(connection, controlled)
                self._observation_fault("append.after_artifacts")
                self._insert_model_calls(connection, controlled)
                self._observation_fault("append.after_model_calls")
                self._insert_parent(
                    connection,
                    controlled,
                    raw,
                    document_sha256,
                    size_bytes,
                )
                self._observation_fault("append.after_observation")
                stored = observation_from_connection(
                    connection,
                    controlled.candidate_run_id,
                    controlled.ledger_sequence,
                )
                if stored is None or stored.authority != controlled:
                    raise _error(M6UpgradeExecutionObservationFailureCode.STORED_AUTHORITY_INVALID)
                self._observation_fault("append.before_commit")
                return stored.authority
        except M6UpgradeExecutionObservationError:
            raise
        except RepositoryIntegrityError as exc:
            raise _error(M6UpgradeExecutionObservationFailureCode.STORED_AUTHORITY_INVALID) from exc
        except ConcurrentModification as exc:
            raise _error(M6UpgradeExecutionObservationFailureCode.STORAGE_REJECTED) from exc
        except sqlite3.IntegrityError as exc:
            raise _error(M6UpgradeExecutionObservationFailureCode.STORAGE_REJECTED) from exc
        except sqlite3.DatabaseError as exc:
            raise _error(M6UpgradeExecutionObservationFailureCode.STORAGE_REJECTED) from exc

    def load(
        self,
        candidate_run_id: str,
        execution_scope_authority_id: str,
        ledger_sequence: int,
    ) -> M6UpgradeSampleExecutionObservationAuthority:
        run_id, scope_id, sequence = _require_lookup(
            candidate_run_id,
            execution_scope_authority_id,
            ledger_sequence,
        )
        try:
            with self._read() as connection:
                stored_scope = self._scope(connection, run_id)
                if stored_scope.authority.execution_scope_authority_id != scope_id:
                    raise _error(M6UpgradeExecutionObservationFailureCode.SCOPE_MISMATCH)
                stored = observation_from_connection(connection, run_id, sequence)
                if stored is None:
                    raise _error(M6UpgradeExecutionObservationFailureCode.OBSERVATION_NOT_FOUND)
                return stored.authority
        except M6UpgradeExecutionObservationError:
            raise
        except RepositoryIntegrityError as exc:
            raise _error(M6UpgradeExecutionObservationFailureCode.STORED_AUTHORITY_INVALID) from exc
        except sqlite3.DatabaseError as exc:
            raise _error(M6UpgradeExecutionObservationFailureCode.STORED_AUTHORITY_INVALID) from exc


__all__ = ["SQLiteM6UpgradeExecutionObservationRepository"]
