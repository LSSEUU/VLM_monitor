"""Protocol-V3 SQLite persistence for exact M6 Observation V2 authorities."""

from __future__ import annotations

import sqlite3
from typing import NoReturn

from labcourt.contracts.m6_upgrade_execution_ledger import M6UpgradeExecutionScopeAuthority
from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeSampleExecutionObservationAuthorityV2,
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
from labcourt.ports.m6_upgrade_execution_observation import (
    M6UpgradeExecutionObservationError,
    M6UpgradeExecutionObservationFailureCode,
)

from ._sqlite_m6_upgrade_execution_ledger_codec import (
    M6UpgradeLedgerProtocolVersion,
    StoredM6UpgradeScope,
)
from ._sqlite_m6_upgrade_execution_ledger_v3_codec import (
    M6SQLiteUpgradeV3State,
    _load_m6_upgrade_v3_state_from_connection_unchecked,
    stored_scope_v3_from_connection,
)
from ._sqlite_m6_upgrade_execution_observation_codec import (
    MAX_M6_UPGRADE_OBSERVATION_INVENTORY_BYTES,
    canonical_observation_v2,
    observation_v2_document,
)
from ._sqlite_read_session import SQLiteReadSession
from .sqlite_m6_upgrade_execution_ledger import SQLiteM6UpgradeExecutionLedgerRepository
from .sqlite_repository import RepositoryIntegrityError


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


def _translate_v3_error(error: M6UpgradeExecutionLedgerV3Error) -> NoReturn:
    mapping = {
        M6UpgradeExecutionLedgerV3FailureCode.INVALID_ARGUMENT: (
            M6UpgradeExecutionObservationFailureCode.INVALID_ARGUMENT
        ),
        M6UpgradeExecutionLedgerV3FailureCode.SCOPE_NOT_FOUND: (
            M6UpgradeExecutionObservationFailureCode.SCOPE_NOT_FOUND
        ),
        M6UpgradeExecutionLedgerV3FailureCode.SCOPE_CONFLICT: (
            M6UpgradeExecutionObservationFailureCode.SCOPE_MISMATCH
        ),
        M6UpgradeExecutionLedgerV3FailureCode.SCOPE_MISMATCH: (
            M6UpgradeExecutionObservationFailureCode.SCOPE_MISMATCH
        ),
        M6UpgradeExecutionLedgerV3FailureCode.LEDGER_VERSION_UNSUPPORTED: (
            M6UpgradeExecutionObservationFailureCode.LEGACY_LEDGER_UNSUPPORTED
        ),
        M6UpgradeExecutionLedgerV3FailureCode.LEGACY_LEDGER_UNSUPPORTED: (
            M6UpgradeExecutionObservationFailureCode.LEGACY_LEDGER_UNSUPPORTED
        ),
        M6UpgradeExecutionLedgerV3FailureCode.LEDGER_SEALED: (
            M6UpgradeExecutionObservationFailureCode.LEDGER_SEALED
        ),
        M6UpgradeExecutionLedgerV3FailureCode.DOCUMENT_TOO_LARGE: (
            M6UpgradeExecutionObservationFailureCode.DOCUMENT_TOO_LARGE
        ),
        M6UpgradeExecutionLedgerV3FailureCode.STORAGE_REJECTED: (
            M6UpgradeExecutionObservationFailureCode.STORAGE_REJECTED
        ),
    }
    translated = mapping.get(error.reason_code)
    if translated is not None:
        raise _error(translated) from error
    raise _error(M6UpgradeExecutionObservationFailureCode.STORED_AUTHORITY_INVALID) from error


class SQLiteM6UpgradeExecutionObservationV3Repository(SQLiteM6UpgradeExecutionLedgerRepository):
    """Persist exact Observation-V2 authorities across the complete V3 ledger."""

    def _observation_v3_fault(self, phase: str) -> None:
        if not isinstance(phase, str) or not phase:
            raise TypeError("M6 V3 observation fault phase must be a non-empty string")
        if self._fault_injector is not None:
            self._fault_injector(f"m6_upgrade_execution_observation_v3.{phase}")

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
            _translate_ledger_error(exc)

    def begin_execution(
        self,
        scope: M6UpgradeExecutionScopeAuthority,
    ) -> M6UpgradeExecutionScopeAuthority:
        """Begin V3 execution without publishing lower diagnostic chains."""

        failure = M6UpgradeExecutionObservationFailureCode.STORAGE_REJECTED
        try:
            return self._attempt_begin_execution(scope)
        except M6UpgradeExecutionObservationError as error:
            failure = error.reason_code
        except Exception:
            pass
        del self, scope
        raise _error(failure) from None

    @staticmethod
    def _insert_artifacts(
        connection: sqlite3.Connection,
        observation: M6UpgradeSampleExecutionObservationAuthorityV2,
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
        observation: M6UpgradeSampleExecutionObservationAuthorityV2,
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
        observation: M6UpgradeSampleExecutionObservationAuthorityV2,
        raw: str,
        document_sha256: str,
        size_bytes: int,
    ) -> None:
        candidate_case = observation.candidate_case
        anchor = observation.selected_case_audit_anchor
        connection.execute(
            """
            INSERT INTO m6_upgrade_sample_execution_observations(
                run_id, execution_scope_authority_id, ledger_sequence,
                observation_authority_id, command_id,
                execution_dataset_snapshot_id, execution_entry_id,
                sample_id, outcome, observation_schema_version,
                selected_case_audit_anchor_id, case_audit_action,
                case_audit_object_kind, case_audit_object_id,
                case_id, case_revision, case_document_sha256,
                case_audit_sequence, case_audit_entry_hash,
                artifact_count, model_call_count,
                observation_json, document_sha256, size_bytes
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
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
                "v2",
                anchor.selected_case_audit_anchor_id if anchor is not None else None,
                anchor.action.value if anchor is not None else None,
                anchor.object_ref.kind.value if anchor is not None else None,
                anchor.object_ref.artifact_id if anchor is not None else None,
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

    def _attempt_append(
        self,
        observation: M6UpgradeSampleExecutionObservationAuthorityV2,
    ) -> M6UpgradeSampleExecutionObservationAuthorityV2:
        controlled = canonical_observation_v2(observation)
        raw, document_sha256, size_bytes = observation_v2_document(controlled)
        try:
            with self._immediate() as connection:
                state = self._load_state(
                    connection,
                    controlled.candidate_run_id,
                    controlled.execution_scope_authority_id,
                )
                scope = state.stored_scope.authority
                if state.seal is not None:
                    raise _error(M6UpgradeExecutionObservationFailureCode.LEDGER_SEALED)
                collisions = tuple(
                    stored
                    for stored in state.observations
                    if (
                        stored.authority.ledger_sequence == controlled.ledger_sequence
                        or stored.authority.observation_authority_id
                        == controlled.observation_authority_id
                        or stored.authority.execution_entry.execution_entry_id
                        == controlled.execution_entry.execution_entry_id
                        or stored.authority.execution_entry.sample_id
                        == controlled.execution_entry.sample_id
                    )
                )
                if collisions:
                    stored_retry = collisions[0] if len(collisions) == 1 else None
                    if (
                        stored_retry is not None
                        and stored_retry.authority.ledger_sequence == controlled.ledger_sequence
                        and stored_retry.authority.observation_authority_id
                        == controlled.observation_authority_id
                        and len(state.observations) == len(state.records) + 1
                        and len(state.commitments) == len(state.records)
                        and stored_retry.authority == controlled
                        and stored_retry.document_sha256 == document_sha256
                        and stored_retry.size_bytes == size_bytes
                    ):
                        return stored_retry.authority
                    raise _error(M6UpgradeExecutionObservationFailureCode.OBSERVATION_CONFLICT)
                if len(state.observations) > len(state.records):
                    raise _error(
                        M6UpgradeExecutionObservationFailureCode.PENDING_OBSERVATION_EXISTS
                    )
                if (
                    sum(item.size_bytes for item in state.observations) + size_bytes
                    > MAX_M6_UPGRADE_OBSERVATION_INVENTORY_BYTES
                ):
                    raise _error(M6UpgradeExecutionObservationFailureCode.DOCUMENT_TOO_LARGE)
                entries = scope.execution_dataset.entries
                sequence = len(state.records)
                if (
                    controlled.command_id != scope.command.command_id
                    or controlled.execution_dataset_snapshot_id
                    != scope.execution_dataset.execution_dataset_snapshot_id
                    or controlled.ledger_sequence != sequence
                    or sequence >= len(entries)
                    or controlled.execution_entry != entries[sequence]
                ):
                    raise _error(M6UpgradeExecutionObservationFailureCode.OBSERVATION_OUT_OF_ORDER)

                self._insert_artifacts(connection, controlled)
                self._observation_v3_fault("append.after_artifacts")
                self._insert_model_calls(connection, controlled)
                self._observation_v3_fault("append.after_model_calls")
                self._insert_parent(
                    connection,
                    controlled,
                    raw,
                    document_sha256,
                    size_bytes,
                )
                self._observation_v3_fault("append.after_observation")
                readback = self._load_state(
                    connection,
                    controlled.candidate_run_id,
                    controlled.execution_scope_authority_id,
                )
                if (
                    len(readback.observations) != len(state.observations) + 1
                    or readback.observations[-1].authority != controlled
                ):
                    raise _error(M6UpgradeExecutionObservationFailureCode.STORED_AUTHORITY_INVALID)
                self._observation_v3_fault("append.before_commit")
                return readback.observations[-1].authority
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

    def append(
        self,
        observation: M6UpgradeSampleExecutionObservationAuthorityV2,
    ) -> M6UpgradeSampleExecutionObservationAuthorityV2:
        """Append an exact Observation V2 through a payload-free facade."""

        failure = M6UpgradeExecutionObservationFailureCode.STORAGE_REJECTED
        try:
            return self._attempt_append(observation)
        except M6UpgradeExecutionObservationError as error:
            failure = error.reason_code
        except Exception:
            pass
        del self, observation
        raise _error(failure) from None

    def _attempt_load(
        self,
        candidate_run_id: str,
        execution_scope_authority_id: str,
        ledger_sequence: int,
    ) -> M6UpgradeSampleExecutionObservationAuthorityV2:
        run_id, scope_id, sequence = _require_lookup(
            candidate_run_id,
            execution_scope_authority_id,
            ledger_sequence,
        )
        try:
            with self._read() as connection:
                state = self._load_state(connection, run_id, scope_id)
                if sequence >= len(state.observations):
                    raise _error(M6UpgradeExecutionObservationFailureCode.OBSERVATION_NOT_FOUND)
                return state.observations[sequence].authority
        except M6UpgradeExecutionObservationError:
            raise
        except RepositoryIntegrityError as exc:
            raise _error(M6UpgradeExecutionObservationFailureCode.STORED_AUTHORITY_INVALID) from exc
        except sqlite3.DatabaseError as exc:
            raise _error(M6UpgradeExecutionObservationFailureCode.STORED_AUTHORITY_INVALID) from exc

    def load(
        self,
        candidate_run_id: str,
        execution_scope_authority_id: str,
        ledger_sequence: int,
    ) -> M6UpgradeSampleExecutionObservationAuthorityV2:
        """Load one Observation V2 without retaining lookup or storage payloads."""

        failure = M6UpgradeExecutionObservationFailureCode.STORAGE_REJECTED
        try:
            return self._attempt_load(
                candidate_run_id,
                execution_scope_authority_id,
                ledger_sequence,
            )
        except M6UpgradeExecutionObservationError as error:
            failure = error.reason_code
        except Exception:
            pass
        del self, candidate_run_id, execution_scope_authority_id, ledger_sequence
        raise _error(failure) from None


__all__ = ["SQLiteM6UpgradeExecutionObservationV3Repository"]
