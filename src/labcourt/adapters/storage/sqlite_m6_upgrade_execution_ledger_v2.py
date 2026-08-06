"""Observation-backed SQLite persistence for the M6 upgrade ledger V2."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn, cast

from pydantic import ValidationError

from labcourt.contracts.m6_replay_locked import M6LockedModelCallLayer
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6_UPGRADE_LEDGER_GENESIS_HASH,
    MAX_M6_UPGRADE_LEDGER_LINKS,
    MAX_M6_UPGRADE_LEDGER_LINKS_PER_SAMPLE,
    M6UpgradeExecutionLedgerSealV2,
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
    M6UpgradePhysicalArtifactRef,
    M6UpgradePhysicalArtifactSource,
)
from labcourt.contracts.references import require_reference_token
from labcourt.exceptions import ConcurrentModification
from labcourt.ports.m6_upgrade_execution_ledger import (
    M6UpgradeExecutionLedgerError,
    M6UpgradeExecutionLedgerFailureCode,
    M6UpgradeSampleArtifactVerifier,
)
from labcourt.ports.m6_upgrade_execution_ledger_v2 import (
    M6UpgradeExecutionLedgerV2Error,
    M6UpgradeExecutionLedgerV2FailureCode,
    M6UpgradeExecutionLedgerV2Status,
    M6UpgradeExecutionResumeV2,
)
from labcourt.ports.m6_upgrade_execution_observation import (
    M6UpgradeExecutionObservationError,
    M6UpgradeExecutionObservationFailureCode,
)
from labcourt.ports.m6_upgrade_pending_sample_commitment import (
    M6UpgradePendingSampleCommitmentError,
    M6UpgradePendingSampleCommitmentFailureCode,
)

from ._sqlite_m6_live_read_cut import (
    M6SQLiteReadSession,
    is_m6_sqlite_read_session,
)
from ._sqlite_m6_upgrade_execution_ledger_codec import (
    MAX_M6_UPGRADE_SCOPE_BYTES,
    MAX_M6_UPGRADE_SEAL_BYTES,
    M6UpgradeLedgerProtocolVersion,
    StoredM6UpgradeScope,
    _preflight_stored_inventory,
    canonical_model,
    contract_document,
    ledger_protocol_from_connection,
    scope_from_row,
)
from ._sqlite_m6_upgrade_execution_ledger_v2_codec import (
    records_v2_from_connection,
    seal_v2_from_row,
)
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
from ._sqlite_read_session import SQLiteReadSession
from .sqlite_m6_upgrade_execution_ledger import SQLiteM6UpgradeExecutionLedgerRepository
from .sqlite_repository import Clock, RepositoryIntegrityError, _row_int, _row_str


def _error(
    code: M6UpgradeExecutionLedgerV2FailureCode,
) -> M6UpgradeExecutionLedgerV2Error:
    return M6UpgradeExecutionLedgerV2Error(code)


def _require_lookup(run_id: object, execution_scope_authority_id: object) -> tuple[str, str]:
    try:
        if not isinstance(run_id, str):
            raise TypeError
        controlled_run_id = require_reference_token(run_id, "M6 V2 upgrade ledger run_id")
    except (TypeError, ValueError) as exc:
        raise _error(M6UpgradeExecutionLedgerV2FailureCode.INVALID_ARGUMENT) from exc
    if (
        not isinstance(execution_scope_authority_id, str)
        or len(execution_scope_authority_id) != 64
        or any(character not in "0123456789abcdef" for character in execution_scope_authority_id)
    ):
        raise _error(M6UpgradeExecutionLedgerV2FailureCode.INVALID_ARGUMENT)
    return controlled_run_id, execution_scope_authority_id


def _translate_v1_error(error: M6UpgradeExecutionLedgerError) -> NoReturn:
    mapping = {
        M6UpgradeExecutionLedgerFailureCode.INVALID_ARGUMENT: (
            M6UpgradeExecutionLedgerV2FailureCode.INVALID_ARGUMENT
        ),
        M6UpgradeExecutionLedgerFailureCode.SCOPE_NOT_FOUND: (
            M6UpgradeExecutionLedgerV2FailureCode.SCOPE_NOT_FOUND
        ),
        M6UpgradeExecutionLedgerFailureCode.SCOPE_CONFLICT: (
            M6UpgradeExecutionLedgerV2FailureCode.SCOPE_CONFLICT
        ),
        M6UpgradeExecutionLedgerFailureCode.SCOPE_MISMATCH: (
            M6UpgradeExecutionLedgerV2FailureCode.SCOPE_MISMATCH
        ),
        M6UpgradeExecutionLedgerFailureCode.LEDGER_VERSION_UNSUPPORTED: (
            M6UpgradeExecutionLedgerV2FailureCode.LEDGER_VERSION_UNSUPPORTED
        ),
        M6UpgradeExecutionLedgerFailureCode.PHYSICAL_ARTIFACT_REJECTED: (
            M6UpgradeExecutionLedgerV2FailureCode.PHYSICAL_ARTIFACT_REJECTED
        ),
        M6UpgradeExecutionLedgerFailureCode.PHYSICAL_ARTIFACT_CONFLICT: (
            M6UpgradeExecutionLedgerV2FailureCode.PHYSICAL_ARTIFACT_REJECTED
        ),
        M6UpgradeExecutionLedgerFailureCode.SAMPLE_CONFLICT: (
            M6UpgradeExecutionLedgerV2FailureCode.SAMPLE_CONFLICT
        ),
        M6UpgradeExecutionLedgerFailureCode.SAMPLE_OUT_OF_ORDER: (
            M6UpgradeExecutionLedgerV2FailureCode.SAMPLE_OUT_OF_ORDER
        ),
        M6UpgradeExecutionLedgerFailureCode.LEDGER_SEALED: (
            M6UpgradeExecutionLedgerV2FailureCode.LEDGER_SEALED
        ),
        M6UpgradeExecutionLedgerFailureCode.LEDGER_INCOMPLETE: (
            M6UpgradeExecutionLedgerV2FailureCode.LEDGER_INCOMPLETE
        ),
        M6UpgradeExecutionLedgerFailureCode.LEDGER_NOT_SEALED: (
            M6UpgradeExecutionLedgerV2FailureCode.LEDGER_NOT_SEALED
        ),
        M6UpgradeExecutionLedgerFailureCode.DOCUMENT_TOO_LARGE: (
            M6UpgradeExecutionLedgerV2FailureCode.DOCUMENT_TOO_LARGE
        ),
        M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID: (
            M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID
        ),
        M6UpgradeExecutionLedgerFailureCode.SQLITE_REJECTED: (
            M6UpgradeExecutionLedgerV2FailureCode.STORAGE_REJECTED
        ),
    }
    translated = mapping.get(error.reason_code)
    if translated is not None:
        raise _error(translated) from error
    raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID) from error


def _translate_observation_error(error: M6UpgradeExecutionObservationError) -> NoReturn:
    mapping = {
        M6UpgradeExecutionObservationFailureCode.INVALID_ARGUMENT: (
            M6UpgradeExecutionLedgerV2FailureCode.INVALID_ARGUMENT
        ),
        M6UpgradeExecutionObservationFailureCode.SCOPE_NOT_FOUND: (
            M6UpgradeExecutionLedgerV2FailureCode.SCOPE_NOT_FOUND
        ),
        M6UpgradeExecutionObservationFailureCode.SCOPE_MISMATCH: (
            M6UpgradeExecutionLedgerV2FailureCode.SCOPE_MISMATCH
        ),
        M6UpgradeExecutionObservationFailureCode.OBSERVATION_NOT_FOUND: (
            M6UpgradeExecutionLedgerV2FailureCode.OBSERVATION_NOT_FOUND
        ),
        M6UpgradeExecutionObservationFailureCode.LEGACY_LEDGER_UNSUPPORTED: (
            M6UpgradeExecutionLedgerV2FailureCode.LEGACY_LEDGER_UNSUPPORTED
        ),
        M6UpgradeExecutionObservationFailureCode.DOCUMENT_TOO_LARGE: (
            M6UpgradeExecutionLedgerV2FailureCode.DOCUMENT_TOO_LARGE
        ),
        M6UpgradeExecutionObservationFailureCode.STORAGE_REJECTED: (
            M6UpgradeExecutionLedgerV2FailureCode.STORAGE_REJECTED
        ),
    }
    translated = mapping.get(error.reason_code)
    if translated is not None:
        raise _error(translated) from error
    raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID) from error


def _translate_commitment_error(error: M6UpgradePendingSampleCommitmentError) -> NoReturn:
    mapping = {
        M6UpgradePendingSampleCommitmentFailureCode.INVALID_ARGUMENT: (
            M6UpgradeExecutionLedgerV2FailureCode.INVALID_ARGUMENT
        ),
        M6UpgradePendingSampleCommitmentFailureCode.SCOPE_NOT_FOUND: (
            M6UpgradeExecutionLedgerV2FailureCode.SCOPE_NOT_FOUND
        ),
        M6UpgradePendingSampleCommitmentFailureCode.SCOPE_MISMATCH: (
            M6UpgradeExecutionLedgerV2FailureCode.SCOPE_MISMATCH
        ),
        M6UpgradePendingSampleCommitmentFailureCode.OBSERVATION_NOT_FOUND: (
            M6UpgradeExecutionLedgerV2FailureCode.OBSERVATION_NOT_FOUND
        ),
        M6UpgradePendingSampleCommitmentFailureCode.COMMITMENT_NOT_FOUND: (
            M6UpgradeExecutionLedgerV2FailureCode.COMMITMENT_NOT_FOUND
        ),
        M6UpgradePendingSampleCommitmentFailureCode.COMMITMENT_CONFLICT: (
            M6UpgradeExecutionLedgerV2FailureCode.COMMITMENT_CONFLICT
        ),
        M6UpgradePendingSampleCommitmentFailureCode.COMMITMENT_OUT_OF_ORDER: (
            M6UpgradeExecutionLedgerV2FailureCode.SAMPLE_OUT_OF_ORDER
        ),
        M6UpgradePendingSampleCommitmentFailureCode.LEGACY_LEDGER_UNSUPPORTED: (
            M6UpgradeExecutionLedgerV2FailureCode.LEGACY_LEDGER_UNSUPPORTED
        ),
        M6UpgradePendingSampleCommitmentFailureCode.LEDGER_SEALED: (
            M6UpgradeExecutionLedgerV2FailureCode.LEDGER_SEALED
        ),
        M6UpgradePendingSampleCommitmentFailureCode.DOCUMENT_TOO_LARGE: (
            M6UpgradeExecutionLedgerV2FailureCode.DOCUMENT_TOO_LARGE
        ),
        M6UpgradePendingSampleCommitmentFailureCode.STORAGE_REJECTED: (
            M6UpgradeExecutionLedgerV2FailureCode.STORAGE_REJECTED
        ),
    }
    translated = mapping.get(error.reason_code)
    if translated is not None:
        raise _error(translated) from error
    raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID) from error


def _observation_closes_record(
    observation: M6UpgradeSampleExecutionObservationAuthority,
    record: M6UpgradeSampleExecutionRecordV2,
) -> bool:
    if (
        observation.observation_authority_id != record.observation_authority_id
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

    observed_non_model = {
        (item.source, item.kind, item.artifact_id, item.usage) for item in observation.artifacts
    }
    record_non_model = {
        (link.artifact.source, link.artifact.kind, link.artifact.artifact_id, link.usage)
        for link in record.artifact_links
        if not link.artifact.kind.value.startswith("MODEL_")
    }
    record_non_model_count = sum(
        not link.artifact.kind.value.startswith("MODEL_") for link in record.artifact_links
    )
    if (
        len(observation.artifacts) != record_non_model_count
        or observed_non_model != record_non_model
    ):
        return False

    source_by_layer = {
        M6LockedModelCallLayer.SCREENING: M6UpgradePhysicalArtifactSource.M3_SCREENING_MODEL,
        M6LockedModelCallLayer.HEARING: M6UpgradePhysicalArtifactSource.M4_HEARING_MODEL,
    }
    observed_requests = {
        (source_by_layer[item.layer], item.request_id) for item in observation.model_calls
    }
    record_requests = {
        (link.artifact.source, link.artifact.artifact_id)
        for link in record.artifact_links
        if link.artifact.kind == M6UpgradePhysicalArtifactKind.MODEL_REQUEST
    }
    record_request_count = sum(
        link.artifact.kind == M6UpgradePhysicalArtifactKind.MODEL_REQUEST
        for link in record.artifact_links
    )
    return len(observation.model_calls) == record_request_count and (
        observed_requests == record_requests
    )


@dataclass(frozen=True, slots=True)
class M6SQLiteUpgradeV2State:
    stored_scope: StoredM6UpgradeScope
    records: tuple[M6UpgradeSampleExecutionRecordV2, ...]
    observations: tuple[StoredM6UpgradeExecutionObservation, ...]
    commitments: tuple[StoredM6UpgradePendingSampleCommitment, ...]
    current_audit_head_sequence: int
    current_audit_head_hash: str
    seal: M6UpgradeExecutionLedgerSealV2 | None

    @property
    def ledger_head_hash(self) -> str:
        if not self.records:
            return M6_UPGRADE_LEDGER_GENESIS_HASH
        return self.records[-1].sample_execution_record_id


class SQLiteM6UpgradeExecutionLedgerV2Repository(SQLiteM6UpgradeExecutionLedgerRepository):
    """Consume exact durable commitments into an observation-backed V2 ledger."""

    def __init__(
        self,
        database_path: str | Path,
        busy_timeout_ms: int,
        clock: Clock | None = None,
        *,
        sample_artifact_verifier: M6UpgradeSampleArtifactVerifier | None = None,
        fault_injector: Callable[[str], None] | None = None,
    ) -> None:
        super().__init__(
            database_path,
            busy_timeout_ms,
            clock=clock,
            fault_injector=fault_injector,
        )
        self._sample_artifact_verifier = sample_artifact_verifier

    def _v2_fault(self, phase: str) -> None:
        if not isinstance(phase, str) or not phase:
            raise TypeError("M6 V2 ledger fault phase must be a non-empty string")
        if self._fault_injector is not None:
            self._fault_injector(f"m6_upgrade_execution_ledger_v2.{phase}")

    @staticmethod
    def _stored_scope_v2(
        connection: SQLiteReadSession,
        run_id: str,
        execution_scope_authority_id: str,
    ) -> StoredM6UpgradeScope:
        protocol = ledger_protocol_from_connection(connection, run_id)
        if protocol is None:
            raise _error(M6UpgradeExecutionLedgerV2FailureCode.SCOPE_NOT_FOUND)
        if protocol.execution_scope_authority_id != execution_scope_authority_id:
            raise _error(M6UpgradeExecutionLedgerV2FailureCode.SCOPE_MISMATCH)
        if protocol.version == M6UpgradeLedgerProtocolVersion.V1:
            raise _error(M6UpgradeExecutionLedgerV2FailureCode.LEGACY_LEDGER_UNSUPPORTED)
        if protocol.version != M6UpgradeLedgerProtocolVersion.V2:
            raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID)
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
            _translate_v1_error(exc)
        if budget.item_count != 1:
            raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID)
        row = connection.execute(
            "SELECT * FROM m6_upgrade_execution_scopes WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        if row is None:
            raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID)
        try:
            stored = scope_from_row(row)
        except M6UpgradeExecutionLedgerError as exc:
            _translate_v1_error(exc)
        if stored.authority.execution_scope_authority_id != execution_scope_authority_id:
            raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID)
        return stored

    @staticmethod
    def _bounded_count(
        connection: SQLiteReadSession,
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
                raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID)
            count = _row_int(row, "item_count")
        except M6UpgradeExecutionLedgerV2Error:
            raise
        except (IndexError, KeyError, TypeError, RepositoryIntegrityError) as exc:
            raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID) from exc
        if count > limit:
            raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID)
        return count

    @staticmethod
    def _seal_row_v2(
        connection: SQLiteReadSession,
        run_id: str,
    ) -> sqlite3.Row | None:
        small = connection.execute(
            """
            SELECT seal_schema_version, size_bytes,
                   typeof(seal_json) AS json_type,
                   length(CAST(seal_json AS BLOB)) AS actual_size_bytes
            FROM m6_upgrade_execution_ledger_seals WHERE run_id = ?
            """,
            (run_id,),
        ).fetchone()
        if small is None:
            return None
        try:
            version = _row_str(small, "seal_schema_version")
            size_bytes = _row_int(small, "size_bytes")
            json_type = _row_str(small, "json_type")
            actual_size_bytes = _row_int(small, "actual_size_bytes")
        except (IndexError, KeyError, TypeError, RepositoryIntegrityError) as exc:
            raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID) from exc
        if size_bytes > MAX_M6_UPGRADE_SEAL_BYTES or actual_size_bytes > MAX_M6_UPGRADE_SEAL_BYTES:
            raise _error(M6UpgradeExecutionLedgerV2FailureCode.DOCUMENT_TOO_LARGE)
        if (
            version != "v2"
            or json_type != "text"
            or size_bytes < 1
            or size_bytes != actual_size_bytes
        ):
            raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID)
        row = connection.execute(
            "SELECT * FROM m6_upgrade_execution_ledger_seals WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        if row is None:
            raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID)
        return cast(sqlite3.Row, row)

    @staticmethod
    def _validate_observation_scope(
        observation: M6UpgradeSampleExecutionObservationAuthority,
        stored_scope: StoredM6UpgradeScope,
        sequence: int,
    ) -> None:
        scope = stored_scope.authority
        entries = scope.execution_dataset.entries
        if (
            sequence >= len(entries)
            or observation.execution_scope_authority_id != scope.execution_scope_authority_id
            or observation.candidate_run_id != scope.candidate_run_id
            or observation.command_id != scope.command.command_id
            or observation.execution_dataset_snapshot_id
            != scope.execution_dataset.execution_dataset_snapshot_id
            or observation.ledger_sequence != sequence
            or observation.execution_entry != entries[sequence]
        ):
            raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID)

    @staticmethod
    def _validate_case_cut(
        snapshot_records: tuple[M6UpgradeSampleExecutionRecordV2, ...],
        observations: tuple[StoredM6UpgradeExecutionObservation, ...],
        stored_scope: StoredM6UpgradeScope,
        current_audit_head_sequence: int,
    ) -> None:
        start = stored_scope.authority.execution_start_audit_head_sequence
        cases = tuple(
            record.candidate_case
            for record in snapshot_records
            if record.candidate_case is not None
        ) + tuple(
            observation.authority.candidate_case
            for observation in observations[len(snapshot_records) :]
            if observation.authority.candidate_case is not None
        )
        if any(
            case.case_audit_sequence <= start
            or case.case_audit_sequence > current_audit_head_sequence
            for case in cases
        ):
            raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID)

    @staticmethod
    def _validate_prefix_identity_closure(
        records: tuple[M6UpgradeSampleExecutionRecordV2, ...],
        commitments: tuple[StoredM6UpgradePendingSampleCommitment, ...],
    ) -> None:
        pending_records = (
            (commitments[len(records)].authority.sample_execution_record,)
            if len(commitments) > len(records)
            else ()
        )
        complete_prefix = (*records, *pending_records)
        try:
            validate_m6_upgrade_v2_prefix_identity_closure(complete_prefix)
        except ValueError as exc:
            raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID) from exc

    def _load_snapshot(
        self,
        connection: SQLiteReadSession,
        stored_scope: StoredM6UpgradeScope,
    ) -> M6SQLiteUpgradeV2State:
        scope = stored_scope.authority
        expected_count = len(scope.execution_dataset.entries)
        try:
            records = records_v2_from_connection(connection, stored_scope)
            current_head_sequence, current_head_hash = self._validated_run_audit_head(
                connection,
                stored_scope,
            )
        except M6UpgradeExecutionLedgerV2Error:
            raise
        except M6UpgradeExecutionLedgerError as exc:
            _translate_v1_error(exc)

        observation_count = self._bounded_count(
            connection,
            table="m6_upgrade_sample_execution_observations",
            run_id=scope.candidate_run_id,
            limit=expected_count + 1,
        )
        commitment_count = self._bounded_count(
            connection,
            table="m6_upgrade_pending_sample_commitments",
            run_id=scope.candidate_run_id,
            limit=expected_count + 1,
        )
        sample_count = len(records)
        seal_row = self._seal_row_v2(connection, scope.candidate_run_id)
        if seal_row is not None:
            if not (sample_count == observation_count == commitment_count == expected_count):
                raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID)
        elif not (
            sample_count <= expected_count
            and observation_count in {sample_count, sample_count + 1}
            and commitment_count in {sample_count, sample_count + 1}
            and commitment_count <= observation_count
            and (
                sample_count < expected_count
                or observation_count == commitment_count == sample_count
            )
        ):
            raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID)

        try:
            observation_budget = _preflight_stored_inventory(
                connection,
                table="m6_upgrade_sample_execution_observations",
                size_column="size_bytes",
                json_column="observation_json",
                where_sql="run_id = ?",
                where_parameters=(scope.candidate_run_id,),
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
                where_parameters=(scope.candidate_run_id,),
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
                where_parameters=(scope.candidate_run_id,),
                max_items=expected_count + 1,
                max_item_bytes=MAX_M6_UPGRADE_PENDING_RECORD_BYTES,
                max_inventory_bytes=MAX_M6_UPGRADE_PENDING_RECORD_INVENTORY_BYTES,
            )
        except M6UpgradeExecutionLedgerError as exc:
            _translate_v1_error(exc)
        if (
            observation_budget.item_count != observation_count
            or commitment_budget.item_count != commitment_count
            or commitment_record_budget.item_count != commitment_count
        ):
            raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID)
        observations_list: list[StoredM6UpgradeExecutionObservation] = []
        for sequence in range(observation_count):
            try:
                stored_observation = observation_from_connection(
                    connection,
                    scope.candidate_run_id,
                    sequence,
                )
            except M6UpgradeExecutionObservationError as exc:
                _translate_observation_error(exc)
            if stored_observation is None:
                raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID)
            self._validate_observation_scope(stored_observation.authority, stored_scope, sequence)
            observations_list.append(stored_observation)
        observations = tuple(observations_list)

        child_limit = MAX_M6_UPGRADE_LEDGER_LINKS + MAX_M6_UPGRADE_LEDGER_LINKS_PER_SAMPLE
        non_model_child_count = self._bounded_count(
            connection,
            table="m6_upgrade_observed_non_model_artifacts",
            run_id=scope.candidate_run_id,
            limit=child_limit,
        )
        model_child_count = self._bounded_count(
            connection,
            table="m6_upgrade_observed_model_calls",
            run_id=scope.candidate_run_id,
            limit=child_limit,
        )
        if non_model_child_count != sum(len(item.authority.artifacts) for item in observations):
            raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID)
        if model_child_count != sum(len(item.authority.model_calls) for item in observations):
            raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID)

        commitments_list: list[StoredM6UpgradePendingSampleCommitment] = []
        for sequence in range(commitment_count):
            try:
                stored_commitment = pending_sample_commitment_from_connection(
                    connection,
                    scope.candidate_run_id,
                    scope.execution_scope_authority_id,
                    sequence,
                )
            except M6UpgradePendingSampleCommitmentError as exc:
                _translate_commitment_error(exc)
            if stored_commitment is None:
                raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID)
            commitments_list.append(stored_commitment)
        commitments = tuple(commitments_list)

        for sequence, record in enumerate(records):
            observation = observations[sequence].authority
            commitment = commitments[sequence].authority
            if commitment.sample_execution_record != record or not _observation_closes_record(
                observation, record
            ):
                raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID)

        if observation_count > sample_count:
            pending_observation = observations[sample_count].authority
            if commitment_count > sample_count:
                pending_record = commitments[sample_count].authority.sample_execution_record
                if pending_record.previous_ledger_entry_hash != (
                    records[-1].sample_execution_record_id
                    if records
                    else M6_UPGRADE_LEDGER_GENESIS_HASH
                ) or not _observation_closes_record(pending_observation, pending_record):
                    raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID)

        self._validate_prefix_identity_closure(records, commitments)
        self._validate_case_cut(
            records,
            observations,
            stored_scope,
            current_head_sequence,
        )
        seal: M6UpgradeExecutionLedgerSealV2 | None = None
        if seal_row is not None:
            seal = seal_v2_from_row(connection, seal_row, stored_scope, records)
            try:
                self._validate_seal_audit_cut(
                    connection,
                    stored_scope,
                    seal,
                    current_head_sequence=current_head_sequence,
                )
            except M6UpgradeExecutionLedgerError as exc:
                _translate_v1_error(exc)
        return M6SQLiteUpgradeV2State(
            stored_scope=stored_scope,
            records=records,
            observations=observations,
            commitments=commitments,
            current_audit_head_sequence=current_head_sequence,
            current_audit_head_hash=current_head_hash,
            seal=seal,
        )

    @staticmethod
    def _resume_from_snapshot(snapshot: M6SQLiteUpgradeV2State) -> M6UpgradeExecutionResumeV2:
        scope = snapshot.stored_scope.authority
        sample_count = len(snapshot.records)
        expected_count = len(scope.execution_dataset.entries)
        pending_observation = (
            snapshot.observations[sample_count].authority
            if len(snapshot.observations) > sample_count
            else None
        )
        pending_commitment = (
            snapshot.commitments[sample_count].authority
            if len(snapshot.commitments) > sample_count
            else None
        )
        if snapshot.seal is not None:
            status = M6UpgradeExecutionLedgerV2Status.SEALED
        elif sample_count == expected_count:
            status = M6UpgradeExecutionLedgerV2Status.READY_TO_SEAL
        elif pending_commitment is not None:
            status = M6UpgradeExecutionLedgerV2Status.READY_FOR_LEDGER_APPEND
        elif pending_observation is not None:
            status = M6UpgradeExecutionLedgerV2Status.READY_FOR_COMMITMENT
        else:
            status = M6UpgradeExecutionLedgerV2Status.READY_FOR_OBSERVATION
        return M6UpgradeExecutionResumeV2(
            status=status,
            execution_scope=scope,
            committed_sample_count=sample_count,
            ledger_head_hash=snapshot.ledger_head_hash,
            next_execution_entry=(
                scope.execution_dataset.entries[sample_count]
                if sample_count < expected_count
                else None
            ),
            pending_observation=pending_observation,
            pending_commitment=pending_commitment,
            seal=snapshot.seal,
        )

    def begin_execution(
        self,
        scope: M6UpgradeExecutionScopeAuthority,
    ) -> M6UpgradeExecutionScopeAuthority:
        try:
            controlled = canonical_model(scope, M6UpgradeExecutionScopeAuthority)
            document, document_sha256, size_bytes = contract_document(
                controlled,
                max_bytes=MAX_M6_UPGRADE_SCOPE_BYTES,
            )
        except M6UpgradeExecutionLedgerError as exc:
            _translate_v1_error(exc)
        try:
            with self._immediate() as connection:
                protocol = ledger_protocol_from_connection(
                    connection,
                    controlled.candidate_run_id,
                )
                if protocol is not None:
                    if (
                        protocol.execution_scope_authority_id
                        != controlled.execution_scope_authority_id
                    ):
                        raise _error(M6UpgradeExecutionLedgerV2FailureCode.SCOPE_CONFLICT)
                    if protocol.version != M6UpgradeLedgerProtocolVersion.V2:
                        raise _error(
                            M6UpgradeExecutionLedgerV2FailureCode.LEDGER_VERSION_UNSUPPORTED
                        )
                    observed = self._stored_scope_v2(
                        connection,
                        controlled.candidate_run_id,
                        controlled.execution_scope_authority_id,
                    ).authority
                    if observed != controlled:
                        raise _error(M6UpgradeExecutionLedgerV2FailureCode.SCOPE_CONFLICT)
                    return observed
                connection.execute(
                    """
                    INSERT INTO m6_upgrade_execution_ledger_protocols(
                        run_id, execution_scope_authority_id, protocol_version
                    ) VALUES (?, ?, 'v2')
                    """,
                    (
                        controlled.candidate_run_id,
                        controlled.execution_scope_authority_id,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO m6_upgrade_execution_scopes(
                        run_id, execution_scope_authority_id,
                        command_id, execution_dataset_snapshot_id,
                        candidate_manifest_id, candidate_manifest_document_sha256,
                        candidate_config_sha256, execution_component_authority_id,
                        expected_sample_count,
                        execution_start_audit_head_sequence,
                        execution_start_audit_head_hash,
                        scope_json, document_sha256, size_bytes
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        controlled.candidate_run_id,
                        controlled.execution_scope_authority_id,
                        controlled.command.command_id,
                        controlled.execution_dataset.execution_dataset_snapshot_id,
                        controlled.candidate_manifest.manifest_id,
                        controlled.candidate_manifest_content_sha256,
                        controlled.candidate_config.config_sha256,
                        controlled.execution_component.component_authority_id,
                        len(controlled.execution_dataset.entries),
                        controlled.execution_start_audit_head_sequence,
                        controlled.execution_start_audit_head_hash,
                        document,
                        document_sha256,
                        size_bytes,
                    ),
                )
                self._v2_fault("begin_execution.after_insert")
                readback = self._stored_scope_v2(
                    connection,
                    controlled.candidate_run_id,
                    controlled.execution_scope_authority_id,
                ).authority
                if readback != controlled:
                    raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID)
                self._v2_fault("begin_execution.before_commit")
                return readback
        except M6UpgradeExecutionLedgerV2Error:
            raise
        except M6UpgradeExecutionLedgerError as exc:
            _translate_v1_error(exc)
        except RepositoryIntegrityError as exc:
            raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID) from exc
        except ConcurrentModification as exc:
            raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORAGE_REJECTED) from exc
        except sqlite3.IntegrityError as exc:
            raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORAGE_REJECTED) from exc
        except sqlite3.DatabaseError as exc:
            raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORAGE_REJECTED) from exc

    def resume(  # type: ignore[override]
        self,
        run_id: str,
        execution_scope_authority_id: str,
    ) -> M6UpgradeExecutionResumeV2:
        controlled_run_id, controlled_scope_id = _require_lookup(
            run_id,
            execution_scope_authority_id,
        )
        try:
            with self._read() as connection:
                stored_scope = self._stored_scope_v2(
                    connection,
                    controlled_run_id,
                    controlled_scope_id,
                )
                return self._resume_from_snapshot(self._load_snapshot(connection, stored_scope))
        except M6UpgradeExecutionLedgerV2Error:
            raise
        except M6UpgradeExecutionLedgerError as exc:
            _translate_v1_error(exc)
        except RepositoryIntegrityError as exc:
            raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID) from exc
        except sqlite3.DatabaseError as exc:
            raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID) from exc

    def _verified_artifacts_v2(
        self,
        record: M6UpgradeSampleExecutionRecordV2,
    ) -> tuple[M6UpgradePhysicalArtifactRef, ...]:
        verifier = self._sample_artifact_verifier
        verify = getattr(verifier, "verify_m6_upgrade_sample_artifacts", None)
        if verifier is None or not callable(verify):
            raise _error(M6UpgradeExecutionLedgerV2FailureCode.PHYSICAL_ARTIFACT_REJECTED)
        expected = tuple(link.artifact for link in record.artifact_links)
        try:
            observed = verify(record)
            if type(observed) is not tuple or len(observed) != len(expected):
                raise _error(M6UpgradeExecutionLedgerV2FailureCode.PHYSICAL_ARTIFACT_REJECTED)
            controlled: list[M6UpgradePhysicalArtifactRef] = []
            for artifact in observed:
                if type(artifact) is not M6UpgradePhysicalArtifactRef:
                    raise _error(M6UpgradeExecutionLedgerV2FailureCode.PHYSICAL_ARTIFACT_REJECTED)
                canonical = M6UpgradePhysicalArtifactRef.model_validate(
                    artifact.model_dump(mode="json", exclude_computed_fields=True)
                )
                if canonical != artifact:
                    raise _error(M6UpgradeExecutionLedgerV2FailureCode.PHYSICAL_ARTIFACT_REJECTED)
                controlled.append(canonical)
        except M6UpgradeExecutionLedgerV2Error:
            raise
        except Exception as exc:
            raise _error(M6UpgradeExecutionLedgerV2FailureCode.PHYSICAL_ARTIFACT_REJECTED) from exc
        result = tuple(controlled)
        if result != expected:
            raise _error(M6UpgradeExecutionLedgerV2FailureCode.PHYSICAL_ARTIFACT_REJECTED)
        return result

    @staticmethod
    def _insert_record_v2(
        connection: sqlite3.Connection,
        record: M6UpgradeSampleExecutionRecordV2,
        documents: M6UpgradePendingSampleCommitmentDocuments,
    ) -> None:
        candidate_case = record.candidate_case
        connection.execute(
            """
            INSERT INTO m6_upgrade_sample_executions(
                run_id, execution_scope_authority_id,
                ledger_sequence, previous_ledger_entry_hash,
                command_id, execution_dataset_snapshot_id,
                execution_entry_id, sample_id, outcome,
                case_id, case_revision, case_document_sha256,
                case_audit_sequence, case_audit_entry_hash,
                artifact_link_count, artifact_link_inventory_root_sha256,
                sample_execution_record_id,
                record_json, record_document_sha256, record_size_bytes,
                record_schema_version, observation_authority_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                candidate_case.case_id if candidate_case is not None else None,
                candidate_case.case_revision if candidate_case is not None else None,
                candidate_case.case_document_sha256 if candidate_case is not None else None,
                candidate_case.case_audit_sequence if candidate_case is not None else None,
                candidate_case.case_audit_entry_hash if candidate_case is not None else None,
                record.artifact_link_count,
                record.artifact_link_inventory_root_sha256,
                record.sample_execution_record_id,
                documents.sample_execution_record_json,
                documents.sample_execution_record_document_sha256,
                documents.sample_execution_record_size_bytes,
                "v2",
                record.observation_authority_id,
            ),
        )

    def append_committed_sample(
        self,
        commitment: M6UpgradePendingSampleCommitmentAuthority,
    ) -> M6UpgradeSampleExecutionRecordV2:
        try:
            controlled = canonical_pending_sample_commitment(commitment)
            controlled_documents = pending_sample_commitment_documents(controlled)
        except M6UpgradePendingSampleCommitmentError as exc:
            _translate_commitment_error(exc)
        try:
            with self._immediate() as connection:
                stored_scope = self._stored_scope_v2(
                    connection,
                    controlled.candidate_run_id,
                    controlled.execution_scope_authority_id,
                )
                snapshot = self._load_snapshot(connection, stored_scope)
                sequence = controlled.ledger_sequence
                if sequence >= len(snapshot.commitments):
                    if snapshot.seal is not None:
                        raise _error(M6UpgradeExecutionLedgerV2FailureCode.LEDGER_SEALED)
                    raise _error(M6UpgradeExecutionLedgerV2FailureCode.COMMITMENT_NOT_FOUND)
                stored_commitment = snapshot.commitments[sequence]
                if (
                    stored_commitment.authority != controlled
                    or stored_commitment.documents != controlled_documents
                ):
                    raise _error(M6UpgradeExecutionLedgerV2FailureCode.COMMITMENT_CONFLICT)

                record = stored_commitment.authority.sample_execution_record
                verified_artifacts = self._verified_artifacts_v2(record)
                if sequence < len(snapshot.records):
                    if snapshot.records[sequence] != record:
                        raise _error(M6UpgradeExecutionLedgerV2FailureCode.SAMPLE_CONFLICT)
                    return snapshot.records[sequence]
                if snapshot.seal is not None:
                    raise _error(M6UpgradeExecutionLedgerV2FailureCode.LEDGER_SEALED)
                if (
                    sequence != len(snapshot.records)
                    or len(snapshot.observations) != sequence + 1
                    or len(snapshot.commitments) != sequence + 1
                ):
                    raise _error(M6UpgradeExecutionLedgerV2FailureCode.SAMPLE_OUT_OF_ORDER)

                existing_by_key: dict[tuple[int, int, str, str], M6UpgradePhysicalArtifactRef] = {}
                existing_by_id: dict[str, M6UpgradePhysicalArtifactRef] = {}
                for prior_record in snapshot.records:
                    for link in prior_record.artifact_links:
                        existing_by_key[link.artifact.physical_key] = link.artifact
                        existing_by_id[link.artifact.artifact_ref_id] = link.artifact
                for link, artifact in zip(record.artifact_links, verified_artifacts, strict=True):
                    if link.artifact != artifact:
                        raise _error(
                            M6UpgradeExecutionLedgerV2FailureCode.PHYSICAL_ARTIFACT_REJECTED
                        )
                    prior_by_key = existing_by_key.get(artifact.physical_key)
                    prior_by_id = existing_by_id.get(artifact.artifact_ref_id)
                    if (prior_by_key is not None and prior_by_key != artifact) or (
                        prior_by_id is not None and prior_by_id != artifact
                    ):
                        raise _error(
                            M6UpgradeExecutionLedgerV2FailureCode.PHYSICAL_ARTIFACT_REJECTED
                        )
                    if prior_by_key is None:
                        self._append_artifact(
                            connection,
                            run_id=record.candidate_run_id,
                            execution_scope_authority_id=record.execution_scope_authority_id,
                            artifact=artifact,
                        )
                    existing_by_key[artifact.physical_key] = artifact
                    existing_by_id[artifact.artifact_ref_id] = artifact
                self._v2_fault("append_committed_sample.after_refs")
                for link in record.artifact_links:
                    self._append_link(
                        connection,
                        run_id=record.candidate_run_id,
                        execution_entry_id=record.execution_entry_id,
                        link=link,
                    )
                self._v2_fault("append_committed_sample.after_links")
                self._insert_record_v2(connection, record, stored_commitment.documents)
                self._v2_fault("append_committed_sample.after_sample")

                readback = self._load_snapshot(connection, stored_scope)
                if (
                    len(readback.records) != len(snapshot.records) + 1
                    or readback.records[-1] != record
                    or len(readback.observations) != len(readback.records)
                    or len(readback.commitments) != len(readback.records)
                ):
                    raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID)
                self._v2_fault("append_committed_sample.before_commit")
                return readback.records[-1]
        except M6UpgradeExecutionLedgerV2Error:
            raise
        except M6UpgradeExecutionLedgerError as exc:
            _translate_v1_error(exc)
        except M6UpgradeExecutionObservationError as exc:
            _translate_observation_error(exc)
        except M6UpgradePendingSampleCommitmentError as exc:
            _translate_commitment_error(exc)
        except RepositoryIntegrityError as exc:
            raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID) from exc
        except ConcurrentModification as exc:
            raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORAGE_REJECTED) from exc
        except sqlite3.IntegrityError as exc:
            raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORAGE_REJECTED) from exc
        except sqlite3.DatabaseError as exc:
            raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORAGE_REJECTED) from exc

    @staticmethod
    def _insert_seal_v2(
        connection: sqlite3.Connection,
        seal: M6UpgradeExecutionLedgerSealV2,
    ) -> None:
        document, document_sha256, size_bytes = contract_document(
            seal,
            max_bytes=MAX_M6_UPGRADE_SEAL_BYTES,
        )
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
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                document,
                document_sha256,
                size_bytes,
                "v2",
            ),
        )

    def seal(
        self,
        run_id: str,
        execution_scope_authority_id: str,
    ) -> M6UpgradeExecutionLedgerSealV2:
        controlled_run_id, controlled_scope_id = _require_lookup(
            run_id,
            execution_scope_authority_id,
        )
        try:
            with self._immediate() as connection:
                stored_scope = self._stored_scope_v2(
                    connection,
                    controlled_run_id,
                    controlled_scope_id,
                )
                snapshot = self._load_snapshot(connection, stored_scope)
                if snapshot.seal is not None:
                    return snapshot.seal
                expected_count = len(stored_scope.authority.execution_dataset.entries)
                if not (
                    len(snapshot.records)
                    == len(snapshot.observations)
                    == len(snapshot.commitments)
                    == expected_count
                ):
                    raise _error(M6UpgradeExecutionLedgerV2FailureCode.LEDGER_INCOMPLETE)
                try:
                    seal = M6UpgradeExecutionLedgerSealV2(
                        execution_scope=stored_scope.authority,
                        execution_scope_content_sha256=stored_scope.document_sha256,
                        execution_scope_size_bytes=stored_scope.size_bytes,
                        source_audit_head_sequence=snapshot.current_audit_head_sequence,
                        source_audit_head_hash=snapshot.current_audit_head_hash,
                        sample_executions=snapshot.records,
                    )
                except (TypeError, ValueError, ValidationError) as exc:
                    raise _error(
                        M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID
                    ) from exc
                self._insert_seal_v2(connection, seal)
                self._v2_fault("seal.after_insert")
                readback_row = self._seal_row_v2(connection, controlled_run_id)
                if readback_row is None:
                    raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID)
                readback = seal_v2_from_row(
                    connection,
                    readback_row,
                    stored_scope,
                    snapshot.records,
                )
                if readback != seal:
                    raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID)
                self._v2_fault("seal.before_commit")
                return readback
        except M6UpgradeExecutionLedgerV2Error:
            raise
        except M6UpgradeExecutionLedgerError as exc:
            _translate_v1_error(exc)
        except RepositoryIntegrityError as exc:
            raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID) from exc
        except ConcurrentModification as exc:
            raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORAGE_REJECTED) from exc
        except sqlite3.IntegrityError as exc:
            raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORAGE_REJECTED) from exc
        except sqlite3.DatabaseError as exc:
            raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORAGE_REJECTED) from exc

    def load_sealed(
        self,
        run_id: str,
        execution_scope_authority_id: str,
    ) -> M6UpgradeExecutionLedgerSealV2:
        controlled_run_id, controlled_scope_id = _require_lookup(
            run_id,
            execution_scope_authority_id,
        )
        try:
            with self._read() as connection:
                stored_scope = self._stored_scope_v2(
                    connection,
                    controlled_run_id,
                    controlled_scope_id,
                )
                snapshot = self._load_snapshot(connection, stored_scope)
                if snapshot.seal is None:
                    raise _error(M6UpgradeExecutionLedgerV2FailureCode.LEDGER_NOT_SEALED)
                return snapshot.seal
        except M6UpgradeExecutionLedgerV2Error:
            raise
        except M6UpgradeExecutionLedgerError as exc:
            _translate_v1_error(exc)
        except RepositoryIntegrityError as exc:
            raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID) from exc
        except sqlite3.DatabaseError as exc:
            raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID) from exc


def load_m6_upgrade_v2_state_from_connection(
    repository: SQLiteM6UpgradeExecutionLedgerV2Repository,
    connection: M6SQLiteReadSession,
    run_id: str,
    scope_id: str,
) -> M6SQLiteUpgradeV2State:
    """Load a fully validated V2 state within a caller-owned transaction.

    This boundary never opens, commits, rolls back, or closes a connection. The
    caller must start a transaction before invoking it and remains responsible
    for that transaction after the function returns or raises.
    """
    if not isinstance(repository, SQLiteM6UpgradeExecutionLedgerV2Repository):
        raise _error(M6UpgradeExecutionLedgerV2FailureCode.INVALID_ARGUMENT)
    if not is_m6_sqlite_read_session(connection):
        raise _error(M6UpgradeExecutionLedgerV2FailureCode.INVALID_ARGUMENT)
    controlled_run_id, controlled_scope_id = _require_lookup(run_id, scope_id)
    try:
        if not connection.in_transaction:
            raise _error(M6UpgradeExecutionLedgerV2FailureCode.INVALID_ARGUMENT)
    except sqlite3.Error as exc:
        raise _error(M6UpgradeExecutionLedgerV2FailureCode.INVALID_ARGUMENT) from exc

    try:
        stored_scope = repository._stored_scope_v2(
            connection,
            controlled_run_id,
            controlled_scope_id,
        )
        state = repository._load_snapshot(connection, stored_scope)
        if not connection.in_transaction:
            raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORAGE_REJECTED)
        return state
    except M6UpgradeExecutionLedgerV2Error:
        raise
    except M6UpgradeExecutionLedgerError as exc:
        _translate_v1_error(exc)
    except RepositoryIntegrityError as exc:
        raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID) from exc
    except sqlite3.DatabaseError as exc:
        raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORAGE_REJECTED) from exc


__all__ = [
    "M6SQLiteUpgradeV2State",
    "SQLiteM6UpgradeExecutionLedgerV2Repository",
    "load_m6_upgrade_v2_state_from_connection",
]
