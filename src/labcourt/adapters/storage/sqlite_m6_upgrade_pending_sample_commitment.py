"""Append-only SQLite persistence for exact pre-ledger M6 V2 commitments."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import NoReturn

from labcourt.contracts.m6_regression import MAX_M6_REGRESSION_CASES
from labcourt.contracts.m6_replay_locked import M6LockedModelCallLayer
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6_UPGRADE_LEDGER_GENESIS_HASH,
    MAX_M6_UPGRADE_LEDGER_LINKS,
    MAX_M6_UPGRADE_LEDGER_LINKS_PER_SAMPLE,
    M6UpgradeExecutionScopeAuthority,
    M6UpgradeSampleExecutionRecordV2,
)
from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeSampleExecutionObservationAuthority,
)
from labcourt.contracts.m6_upgrade_pending_sample_commitment import (
    M6UpgradePendingSampleCommitmentAuthority,
)
from labcourt.contracts.m6_upgrade_physical import (
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactSource,
)
from labcourt.contracts.references import require_reference_token
from labcourt.exceptions import ConcurrentModification
from labcourt.ports.m6_upgrade_execution_ledger import (
    M6UpgradeExecutionLedgerError,
    M6UpgradeExecutionLedgerFailureCode,
)
from labcourt.ports.m6_upgrade_execution_ledger_v2 import (
    M6UpgradeExecutionLedgerV2Error,
    M6UpgradeExecutionLedgerV2FailureCode,
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
    MAX_M6_UPGRADE_LEDGER_PREFIX_BYTES,
    MAX_M6_UPGRADE_RECORD_BYTES,
    MAX_M6_UPGRADE_SCOPE_BYTES,
    M6UpgradeLedgerProtocolVersion,
    StoredM6UpgradeScope,
    _preflight_stored_inventory,
    ledger_protocol_from_connection,
    scope_from_row,
)
from ._sqlite_m6_upgrade_execution_ledger_v2_codec import records_v2_from_connection
from ._sqlite_m6_upgrade_execution_observation_codec import (
    MAX_M6_UPGRADE_OBSERVATION_BYTES,
    MAX_M6_UPGRADE_OBSERVATION_INVENTORY_BYTES,
    StoredM6UpgradeExecutionObservation,
    observation_from_connection,
)
from ._sqlite_m6_upgrade_pending_sample_commitment_codec import (
    MAX_M6_UPGRADE_PENDING_COMMITMENT_BYTES,
    MAX_M6_UPGRADE_PENDING_COMMITMENT_INVENTORY_BYTES,
    MAX_M6_UPGRADE_PENDING_RECORD_BYTES,
    MAX_M6_UPGRADE_PENDING_RECORD_INVENTORY_BYTES,
    M6UpgradePendingSampleCommitmentDocuments,
    StoredM6UpgradePendingSampleCommitment,
    canonical_pending_sample_commitment,
    pending_sample_commitment_documents,
    pending_sample_commitment_from_connection,
)
from ._sqlite_m6_upgrade_v2_prefix import (
    validate_m6_upgrade_v2_prefix_identity_closure,
)
from .sqlite_m6_upgrade_execution_ledger import SQLiteM6UpgradeExecutionLedgerRepository
from .sqlite_repository import RepositoryIntegrityError, _row_int


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
            "M6 pending sample commitment candidate run_id",
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


def _translate_ledger_error(error: M6UpgradeExecutionLedgerError) -> NoReturn:
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


def _translate_v2_error(error: M6UpgradeExecutionLedgerV2Error) -> NoReturn:
    mapping = {
        M6UpgradeExecutionLedgerV2FailureCode.INVALID_ARGUMENT: (
            M6UpgradePendingSampleCommitmentFailureCode.INVALID_ARGUMENT
        ),
        M6UpgradeExecutionLedgerV2FailureCode.SCOPE_NOT_FOUND: (
            M6UpgradePendingSampleCommitmentFailureCode.SCOPE_NOT_FOUND
        ),
        M6UpgradeExecutionLedgerV2FailureCode.SCOPE_CONFLICT: (
            M6UpgradePendingSampleCommitmentFailureCode.SCOPE_MISMATCH
        ),
        M6UpgradeExecutionLedgerV2FailureCode.SCOPE_MISMATCH: (
            M6UpgradePendingSampleCommitmentFailureCode.SCOPE_MISMATCH
        ),
        M6UpgradeExecutionLedgerV2FailureCode.LEDGER_VERSION_UNSUPPORTED: (
            M6UpgradePendingSampleCommitmentFailureCode.LEGACY_LEDGER_UNSUPPORTED
        ),
        M6UpgradeExecutionLedgerV2FailureCode.LEGACY_LEDGER_UNSUPPORTED: (
            M6UpgradePendingSampleCommitmentFailureCode.LEGACY_LEDGER_UNSUPPORTED
        ),
        M6UpgradeExecutionLedgerV2FailureCode.DOCUMENT_TOO_LARGE: (
            M6UpgradePendingSampleCommitmentFailureCode.DOCUMENT_TOO_LARGE
        ),
        M6UpgradeExecutionLedgerV2FailureCode.STORAGE_REJECTED: (
            M6UpgradePendingSampleCommitmentFailureCode.STORAGE_REJECTED
        ),
    }
    translated = mapping.get(error.reason_code)
    if translated is not None:
        raise _error(translated) from error
    raise _error(M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID) from error


def _translate_observation_error(error: M6UpgradeExecutionObservationError) -> NoReturn:
    mapping = {
        M6UpgradeExecutionObservationFailureCode.INVALID_ARGUMENT: (
            M6UpgradePendingSampleCommitmentFailureCode.INVALID_ARGUMENT
        ),
        M6UpgradeExecutionObservationFailureCode.SCOPE_NOT_FOUND: (
            M6UpgradePendingSampleCommitmentFailureCode.SCOPE_NOT_FOUND
        ),
        M6UpgradeExecutionObservationFailureCode.SCOPE_MISMATCH: (
            M6UpgradePendingSampleCommitmentFailureCode.SCOPE_MISMATCH
        ),
        M6UpgradeExecutionObservationFailureCode.OBSERVATION_NOT_FOUND: (
            M6UpgradePendingSampleCommitmentFailureCode.OBSERVATION_NOT_FOUND
        ),
        M6UpgradeExecutionObservationFailureCode.LEGACY_LEDGER_UNSUPPORTED: (
            M6UpgradePendingSampleCommitmentFailureCode.LEGACY_LEDGER_UNSUPPORTED
        ),
        M6UpgradeExecutionObservationFailureCode.LEDGER_SEALED: (
            M6UpgradePendingSampleCommitmentFailureCode.LEDGER_SEALED
        ),
        M6UpgradeExecutionObservationFailureCode.DOCUMENT_TOO_LARGE: (
            M6UpgradePendingSampleCommitmentFailureCode.DOCUMENT_TOO_LARGE
        ),
        M6UpgradeExecutionObservationFailureCode.STORAGE_REJECTED: (
            M6UpgradePendingSampleCommitmentFailureCode.STORAGE_REJECTED
        ),
    }
    translated = mapping.get(error.reason_code)
    if translated is not None:
        raise _error(translated) from error
    raise _error(M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID) from error


def _observation_closes_record(
    observation: M6UpgradeSampleExecutionObservationAuthority,
    commitment: M6UpgradePendingSampleCommitmentAuthority,
) -> bool:
    record = commitment.sample_execution_record
    if (
        observation.observation_authority_id != commitment.observation_authority_id
        or observation.execution_scope_authority_id != record.execution_scope_authority_id
        or observation.candidate_run_id != record.candidate_run_id
        or observation.command_id != record.command_id
        or observation.execution_dataset_snapshot_id != record.execution_dataset_snapshot_id
        or observation.execution_entry != record.execution_entry
        or observation.ledger_sequence != record.ledger_sequence
        or observation.outcome != record.outcome
        or observation.candidate_case != record.candidate_case
    ):
        return False

    observed_non_model_items = tuple(
        (item.source, item.kind, item.artifact_id, item.usage) for item in observation.artifacts
    )
    record_non_model_items = tuple(
        (link.artifact.source, link.artifact.kind, link.artifact.artifact_id, link.usage)
        for link in record.artifact_links
        if not link.artifact.kind.value.startswith("MODEL_")
    )
    if len(observed_non_model_items) != len(record_non_model_items) or set(
        observed_non_model_items
    ) != set(record_non_model_items):
        return False

    source_by_layer = {
        M6LockedModelCallLayer.SCREENING: (M6UpgradePhysicalArtifactSource.M3_SCREENING_MODEL),
        M6LockedModelCallLayer.HEARING: M6UpgradePhysicalArtifactSource.M4_HEARING_MODEL,
    }
    observed_requests = {
        (source_by_layer[item.layer], item.request_id) for item in observation.model_calls
    }
    record_request_items = tuple(
        (link.artifact.source, link.artifact.artifact_id)
        for link in record.artifact_links
        if link.artifact.kind == M6UpgradePhysicalArtifactKind.MODEL_REQUEST
    )
    return len(observation.model_calls) == len(record_request_items) and (
        observed_requests == set(record_request_items)
    )


@dataclass(frozen=True)
class _M6UpgradePendingCommitmentStoredState:
    sample_count: int
    observation_count: int
    commitment_count: int
    records: tuple[M6UpgradeSampleExecutionRecordV2, ...]
    observations: tuple[StoredM6UpgradeExecutionObservation, ...]
    commitments: tuple[StoredM6UpgradePendingSampleCommitment, ...]
    ledger_record_bytes: int
    observation_bytes: int
    commitment_bytes: int
    commitment_record_bytes: int


class SQLiteM6UpgradePendingSampleCommitmentRepository(SQLiteM6UpgradeExecutionLedgerRepository):
    """Persist one exact record after observation and before ledger append."""

    def _commitment_fault(self, phase: str) -> None:
        if not isinstance(phase, str) or not phase:
            raise TypeError("M6 commitment fault phase must be a non-empty string")
        if self._fault_injector is not None:
            self._fault_injector(f"m6_upgrade_pending_sample_commitment.{phase}")

    @staticmethod
    def _scope(
        connection: sqlite3.Connection,
        run_id: str,
    ) -> StoredM6UpgradeScope:
        protocol = ledger_protocol_from_connection(connection, run_id)
        if protocol is None:
            raise _error(M6UpgradePendingSampleCommitmentFailureCode.SCOPE_NOT_FOUND)
        if protocol.version != M6UpgradeLedgerProtocolVersion.V2:
            raise _error(M6UpgradePendingSampleCommitmentFailureCode.LEGACY_LEDGER_UNSUPPORTED)
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
            raise _error(M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID)
        row = connection.execute(
            "SELECT * FROM m6_upgrade_execution_scopes WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        if row is None:
            raise _error(M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID)
        try:
            stored = scope_from_row(row)
        except M6UpgradeExecutionLedgerError as exc:
            _translate_ledger_error(exc)
        if stored.authority.execution_scope_authority_id != protocol.execution_scope_authority_id:
            raise _error(M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID)
        return stored

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
    def _counts(connection: sqlite3.Connection, run_id: str) -> tuple[int, int, int, int]:
        row = connection.execute(
            """
            SELECT
                (SELECT COUNT(*) FROM m6_upgrade_sample_executions
                 WHERE run_id = ?) AS sample_count,
                (SELECT COUNT(*) FROM m6_upgrade_sample_execution_observations
                 WHERE run_id = ?) AS observation_count,
                (SELECT COUNT(*) FROM m6_upgrade_pending_sample_commitments
                 WHERE run_id = ?) AS commitment_count,
                (SELECT COUNT(*) FROM m6_upgrade_sample_executions
                 WHERE run_id = ? AND (
                     record_schema_version IS NOT 'v2'
                     OR observation_authority_id IS NULL
                 )) AS legacy_sample_count
            """,
            (run_id, run_id, run_id, run_id),
        ).fetchone()
        try:
            if row is None:
                raise _error(M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID)
            return (
                _row_int(row, "sample_count"),
                _row_int(row, "observation_count"),
                _row_int(row, "commitment_count"),
                _row_int(row, "legacy_sample_count"),
            )
        except M6UpgradePendingSampleCommitmentError:
            raise
        except (IndexError, KeyError, TypeError, RepositoryIntegrityError) as exc:
            raise _error(
                M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID
            ) from exc

    @staticmethod
    def _bounded_count(
        connection: sqlite3.Connection,
        *,
        table: str,
        run_id: str,
        limit: int,
    ) -> int:
        row = connection.execute(
            f"""
            SELECT COUNT(*) AS item_count FROM (
                SELECT 1 FROM {table} WHERE run_id = ? LIMIT ?
            )
            """,
            (run_id, limit + 1),
        ).fetchone()
        try:
            if row is None:
                raise _error(M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID)
            count = _row_int(row, "item_count")
        except M6UpgradePendingSampleCommitmentError:
            raise
        except (IndexError, KeyError, TypeError, RepositoryIntegrityError) as exc:
            raise _error(
                M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID
            ) from exc
        if count > limit:
            raise _error(M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID)
        return count

    @staticmethod
    def _stored_state(
        connection: sqlite3.Connection,
        stored_scope: StoredM6UpgradeScope,
    ) -> _M6UpgradePendingCommitmentStoredState:
        scope = stored_scope.authority
        run_id = scope.candidate_run_id
        sample_count, observation_count, commitment_count, legacy_count = (
            SQLiteM6UpgradePendingSampleCommitmentRepository._counts(connection, run_id)
        )
        if legacy_count:
            raise _error(M6UpgradePendingSampleCommitmentFailureCode.LEGACY_LEDGER_UNSUPPORTED)
        if observation_count < sample_count or commitment_count < sample_count:
            raise _error(M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID)
        expected_count = len(scope.execution_dataset.entries)
        if (
            sample_count > expected_count
            or observation_count > sample_count + 1
            or commitment_count > sample_count + 1
            or commitment_count > observation_count
        ):
            raise _error(M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID)
        try:
            observation_sequences = tuple(
                _row_int(row, "ledger_sequence")
                for row in connection.execute(
                    """
                    SELECT ledger_sequence
                    FROM m6_upgrade_sample_execution_observations
                    WHERE run_id = ? ORDER BY ledger_sequence
                    """,
                    (run_id,),
                )
            )
            commitment_sequences = tuple(
                _row_int(row, "ledger_sequence")
                for row in connection.execute(
                    """
                    SELECT ledger_sequence
                    FROM m6_upgrade_pending_sample_commitments
                    WHERE run_id = ? ORDER BY ledger_sequence
                    """,
                    (run_id,),
                )
            )
        except (IndexError, KeyError, TypeError, RepositoryIntegrityError) as exc:
            raise _error(
                M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID
            ) from exc
        if observation_sequences != tuple(range(observation_count)) or (
            commitment_sequences != tuple(range(commitment_count))
        ):
            raise _error(M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID)
        try:
            ledger_record_budget = _preflight_stored_inventory(
                connection,
                table="m6_upgrade_sample_executions",
                size_column="record_size_bytes",
                json_column="record_json",
                where_sql="run_id = ?",
                where_parameters=(run_id,),
                max_items=expected_count,
                max_item_bytes=MAX_M6_UPGRADE_RECORD_BYTES,
                max_inventory_bytes=MAX_M6_UPGRADE_LEDGER_PREFIX_BYTES,
                prefix_bytes=stored_scope.size_bytes,
            )
            observation_budget = _preflight_stored_inventory(
                connection,
                table="m6_upgrade_sample_execution_observations",
                size_column="size_bytes",
                json_column="observation_json",
                where_sql="run_id = ?",
                where_parameters=(run_id,),
                max_items=expected_count + 1,
                max_item_bytes=MAX_M6_UPGRADE_OBSERVATION_BYTES,
                max_inventory_bytes=MAX_M6_UPGRADE_OBSERVATION_INVENTORY_BYTES,
            )
            commitment_budget = _preflight_stored_inventory(
                connection,
                table="m6_upgrade_pending_sample_commitments",
                size_column="size_bytes",
                json_column="commitment_json",
                where_sql="run_id = ?",
                where_parameters=(run_id,),
                max_items=expected_count + 1,
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
                max_items=expected_count + 1,
                max_item_bytes=MAX_M6_UPGRADE_PENDING_RECORD_BYTES,
                max_inventory_bytes=MAX_M6_UPGRADE_PENDING_RECORD_INVENTORY_BYTES,
            )
        except M6UpgradeExecutionLedgerError as exc:
            _translate_ledger_error(exc)
        if (
            ledger_record_budget.item_count != sample_count
            or observation_budget.item_count != observation_count
            or commitment_budget.item_count != commitment_count
            or commitment_record_budget.item_count != commitment_count
        ):
            raise _error(M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID)
        try:
            records = records_v2_from_connection(connection, stored_scope)
        except M6UpgradeExecutionLedgerV2Error as exc:
            _translate_v2_error(exc)
        if len(records) != sample_count:
            raise _error(M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID)

        observations_list: list[StoredM6UpgradeExecutionObservation] = []
        for sequence in range(observation_count):
            try:
                stored_observation = observation_from_connection(connection, run_id, sequence)
            except M6UpgradeExecutionObservationError as exc:
                _translate_observation_error(exc)
            if stored_observation is None:
                raise _error(M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID)
            observation = stored_observation.authority
            if (
                sequence >= expected_count
                or observation.execution_scope_authority_id != scope.execution_scope_authority_id
                or observation.candidate_run_id != run_id
                or observation.command_id != scope.command.command_id
                or observation.execution_dataset_snapshot_id
                != scope.execution_dataset.execution_dataset_snapshot_id
                or observation.ledger_sequence != sequence
                or observation.execution_entry != scope.execution_dataset.entries[sequence]
            ):
                raise _error(M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID)
            observations_list.append(stored_observation)
        observations = tuple(observations_list)
        child_limit = MAX_M6_UPGRADE_LEDGER_LINKS + MAX_M6_UPGRADE_LEDGER_LINKS_PER_SAMPLE
        if SQLiteM6UpgradePendingSampleCommitmentRepository._bounded_count(
            connection,
            table="m6_upgrade_observed_non_model_artifacts",
            run_id=run_id,
            limit=child_limit,
        ) != sum(
            len(item.authority.artifacts) for item in observations
        ) or SQLiteM6UpgradePendingSampleCommitmentRepository._bounded_count(
            connection,
            table="m6_upgrade_observed_model_calls",
            run_id=run_id,
            limit=child_limit,
        ) != sum(len(item.authority.model_calls) for item in observations):
            raise _error(M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID)

        commitments_list: list[StoredM6UpgradePendingSampleCommitment] = []
        for sequence in range(commitment_count):
            stored_commitment = pending_sample_commitment_from_connection(
                connection,
                run_id,
                scope.execution_scope_authority_id,
                sequence,
            )
            if stored_commitment is None:
                raise _error(M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID)
            commitment = stored_commitment.authority
            if (
                commitment.execution_scope_authority_id != scope.execution_scope_authority_id
                or commitment.candidate_run_id != run_id
                or commitment.command_id != scope.command.command_id
                or commitment.execution_dataset_snapshot_id
                != scope.execution_dataset.execution_dataset_snapshot_id
                or commitment.ledger_sequence != sequence
                or commitment.execution_entry != scope.execution_dataset.entries[sequence]
            ):
                raise _error(M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID)
            if not _observation_closes_record(observations[sequence].authority, commitment):
                raise _error(M6UpgradePendingSampleCommitmentFailureCode.OBSERVATION_MISMATCH)
            if sequence < sample_count:
                if commitment.sample_execution_record != records[sequence]:
                    raise _error(
                        M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID
                    )
            elif (
                sequence != sample_count
                or observation_count != sample_count + 1
                or commitment_count != sample_count + 1
                or not SQLiteM6UpgradePendingSampleCommitmentRepository._record_is_next(
                    scope, records, commitment
                )
            ):
                raise _error(M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID)
            commitments_list.append(stored_commitment)
        commitments = tuple(commitments_list)

        complete_prefix = records + (
            (commitments[sample_count].authority.sample_execution_record,)
            if commitment_count > sample_count
            else ()
        )
        try:
            validate_m6_upgrade_v2_prefix_identity_closure(complete_prefix)
        except ValueError as exc:
            raise _error(
                M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID
            ) from exc

        sealed = (
            connection.execute(
                "SELECT 1 FROM m6_upgrade_execution_ledger_seals WHERE run_id = ?",
                (run_id,),
            ).fetchone()
            is not None
        )
        if sealed and (
            sample_count != expected_count
            or observation_count != sample_count
            or commitment_count != sample_count
        ):
            raise _error(M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID)
        return _M6UpgradePendingCommitmentStoredState(
            sample_count=sample_count,
            observation_count=observation_count,
            commitment_count=commitment_count,
            records=records,
            observations=observations,
            commitments=commitments,
            ledger_record_bytes=ledger_record_budget.canonical_bytes,
            observation_bytes=observation_budget.canonical_bytes,
            commitment_bytes=commitment_budget.canonical_bytes,
            commitment_record_bytes=commitment_record_budget.canonical_bytes,
        )

    @staticmethod
    def _record_is_next(
        scope: M6UpgradeExecutionScopeAuthority,
        records: tuple[M6UpgradeSampleExecutionRecordV2, ...],
        commitment: M6UpgradePendingSampleCommitmentAuthority,
    ) -> bool:
        sequence = len(records)
        entries = scope.execution_dataset.entries
        expected_previous = (
            records[-1].sample_execution_record_id if records else M6_UPGRADE_LEDGER_GENESIS_HASH
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

    def _validate_stored_commitment(
        self,
        connection: sqlite3.Connection,
        stored_scope: StoredM6UpgradeScope,
        commitment: M6UpgradePendingSampleCommitmentAuthority,
        *,
        state: _M6UpgradePendingCommitmentStoredState | None = None,
    ) -> M6UpgradePendingSampleCommitmentAuthority:
        controlled_state = state or self._stored_state(connection, stored_scope)
        sequence = commitment.ledger_sequence
        if sequence >= len(controlled_state.commitments):
            raise _error(M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID)
        stored = controlled_state.commitments[sequence]
        if stored.authority != commitment:
            raise _error(M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID)
        return stored.authority

    def append(
        self,
        commitment: M6UpgradePendingSampleCommitmentAuthority,
    ) -> M6UpgradePendingSampleCommitmentAuthority:
        controlled = canonical_pending_sample_commitment(commitment)
        documents = pending_sample_commitment_documents(controlled)
        try:
            with self._immediate() as connection:
                stored_scope = self._scope(connection, controlled.candidate_run_id)
                scope = stored_scope.authority
                if scope.execution_scope_authority_id != controlled.execution_scope_authority_id:
                    raise _error(M6UpgradePendingSampleCommitmentFailureCode.SCOPE_MISMATCH)

                sealed = (
                    connection.execute(
                        "SELECT 1 FROM m6_upgrade_execution_ledger_seals WHERE run_id = ?",
                        (controlled.candidate_run_id,),
                    ).fetchone()
                    is not None
                )
                if sealed and (
                    connection.execute(
                        """
                        SELECT 1 FROM m6_upgrade_pending_sample_commitments
                        WHERE run_id = ? AND execution_scope_authority_id = ?
                          AND ledger_sequence = ?
                        """,
                        (
                            controlled.candidate_run_id,
                            controlled.execution_scope_authority_id,
                            controlled.ledger_sequence,
                        ),
                    ).fetchone()
                    is None
                ):
                    raise _error(M6UpgradePendingSampleCommitmentFailureCode.LEDGER_SEALED)

                # Validate and preflight the complete persisted prefix before any
                # collision path can decode a stored commitment.  Exact retries
                # must not turn malformed or over-budget authority into an
                # early, partially decoded success path.
                state = self._stored_state(connection, stored_scope)

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
                    if len(collisions) == 1:
                        stored = (
                            state.commitments[controlled.ledger_sequence]
                            if controlled.ledger_sequence < len(state.commitments)
                            else None
                        )
                        if (
                            stored is not None
                            and stored.authority == controlled
                            and stored.documents == documents
                        ):
                            return self._validate_stored_commitment(
                                connection,
                                stored_scope,
                                stored.authority,
                                state=state,
                            )
                    raise _error(M6UpgradePendingSampleCommitmentFailureCode.COMMITMENT_CONFLICT)

                if sealed:
                    raise _error(M6UpgradePendingSampleCommitmentFailureCode.LEDGER_SEALED)

                if state.commitment_count > state.sample_count:
                    raise _error(
                        M6UpgradePendingSampleCommitmentFailureCode.PENDING_COMMITMENT_EXISTS
                    )
                if state.observation_count == state.sample_count:
                    raise _error(M6UpgradePendingSampleCommitmentFailureCode.OBSERVATION_NOT_FOUND)
                if (
                    state.observation_count != state.sample_count + 1
                    or state.commitment_count != state.sample_count
                ):
                    raise _error(
                        M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID
                    )

                observation = state.observations[state.sample_count].authority
                if not _observation_closes_record(observation, controlled):
                    raise _error(M6UpgradePendingSampleCommitmentFailureCode.OBSERVATION_MISMATCH)

                if not self._record_is_next(scope, state.records, controlled):
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

                if (
                    stored_scope.size_bytes
                    + state.ledger_record_bytes
                    + documents.sample_execution_record_size_bytes
                    > MAX_M6_UPGRADE_LEDGER_PREFIX_BYTES
                    or state.commitment_bytes + documents.size_bytes
                    > MAX_M6_UPGRADE_PENDING_COMMITMENT_INVENTORY_BYTES
                    or state.commitment_record_bytes + documents.sample_execution_record_size_bytes
                    > MAX_M6_UPGRADE_PENDING_RECORD_INVENTORY_BYTES
                ):
                    raise _error(M6UpgradePendingSampleCommitmentFailureCode.DOCUMENT_TOO_LARGE)

                self._insert(connection, controlled, documents)
                self._commitment_fault("append.after_insert")
                stored = pending_sample_commitment_from_connection(
                    connection,
                    controlled.candidate_run_id,
                    controlled.execution_scope_authority_id,
                    controlled.ledger_sequence,
                )
                if (
                    stored is None
                    or stored.authority != controlled
                    or stored.documents != documents
                ):
                    raise _error(
                        M6UpgradePendingSampleCommitmentFailureCode.STORED_AUTHORITY_INVALID
                    )
                self._commitment_fault("append.before_commit")
                return stored.authority
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

    def load(
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
                stored_scope = self._scope(connection, run_id)
                if stored_scope.authority.execution_scope_authority_id != scope_id:
                    raise _error(M6UpgradePendingSampleCommitmentFailureCode.SCOPE_MISMATCH)
                state = self._stored_state(connection, stored_scope)
                stored = pending_sample_commitment_from_connection(
                    connection,
                    run_id,
                    scope_id,
                    sequence,
                )
                if stored is None:
                    raise _error(M6UpgradePendingSampleCommitmentFailureCode.COMMITMENT_NOT_FOUND)
                return self._validate_stored_commitment(
                    connection,
                    stored_scope,
                    stored.authority,
                    state=state,
                )
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


__all__ = ["SQLiteM6UpgradePendingSampleCommitmentRepository"]
