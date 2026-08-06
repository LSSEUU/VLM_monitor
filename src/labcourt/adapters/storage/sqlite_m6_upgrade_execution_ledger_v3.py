"""Selected-audit-anchored SQLite persistence for M6 ledger protocol V3."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from pathlib import Path
from typing import NoReturn

from pydantic import ValidationError

from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6UpgradeExecutionLedgerSealV2,
    M6UpgradeExecutionScopeAuthority,
    M6UpgradeSampleExecutionRecordV2,
)
from labcourt.contracts.m6_upgrade_pending_sample_commitment import (
    M6UpgradePendingSampleCommitmentAuthority,
)
from labcourt.contracts.m6_upgrade_physical import M6UpgradePhysicalArtifactRef
from labcourt.contracts.references import require_reference_token
from labcourt.exceptions import ConcurrentModification
from labcourt.ports.m6_upgrade_execution_ledger import (
    M6UpgradeExecutionLedgerError,
    M6UpgradeExecutionLedgerFailureCode,
    M6UpgradeSampleArtifactVerifier,
)
from labcourt.ports.m6_upgrade_execution_ledger_v3 import (
    M6UpgradeExecutionLedgerV3Error,
    M6UpgradeExecutionLedgerV3FailureCode,
    M6UpgradeExecutionLedgerV3Status,
    M6UpgradeExecutionResumeV3,
)
from labcourt.ports.m6_upgrade_pending_sample_commitment import (
    M6UpgradePendingSampleCommitmentError,
    M6UpgradePendingSampleCommitmentFailureCode,
)

from ._sqlite_m6_live_read_cut import M6SQLiteReadSession, is_m6_sqlite_read_session
from ._sqlite_m6_upgrade_execution_ledger_codec import (
    MAX_M6_UPGRADE_SEAL_BYTES,
    M6UpgradeLedgerProtocolVersion,
    StoredM6UpgradeScope,
    contract_document,
)
from ._sqlite_m6_upgrade_execution_ledger_v3_codec import (
    M6SQLiteUpgradeV3State,
    _load_m6_upgrade_v3_state_from_connection_unchecked,
    stored_scope_v3_from_connection,
)
from ._sqlite_m6_upgrade_pending_sample_commitment_codec import (
    M6UpgradePendingSampleCommitmentDocuments,
    canonical_pending_sample_commitment,
    pending_sample_commitment_documents,
)
from ._sqlite_read_session import SQLiteReadSession
from .sqlite_m6_upgrade_execution_ledger import SQLiteM6UpgradeExecutionLedgerRepository
from .sqlite_repository import Clock, RepositoryIntegrityError


def _error(
    code: M6UpgradeExecutionLedgerV3FailureCode,
) -> M6UpgradeExecutionLedgerV3Error:
    return M6UpgradeExecutionLedgerV3Error(code)


def _require_lookup(run_id: object, execution_scope_authority_id: object) -> tuple[str, str]:
    try:
        if not isinstance(run_id, str):
            raise TypeError
        controlled_run_id = require_reference_token(run_id, "M6 V3 upgrade ledger run_id")
    except (TypeError, ValueError) as exc:
        raise _error(M6UpgradeExecutionLedgerV3FailureCode.INVALID_ARGUMENT) from exc
    if (
        not isinstance(execution_scope_authority_id, str)
        or len(execution_scope_authority_id) != 64
        or any(character not in "0123456789abcdef" for character in execution_scope_authority_id)
    ):
        raise _error(M6UpgradeExecutionLedgerV3FailureCode.INVALID_ARGUMENT)
    return controlled_run_id, execution_scope_authority_id


def _translate_base_error(error: M6UpgradeExecutionLedgerError) -> NoReturn:
    mapping = {
        M6UpgradeExecutionLedgerFailureCode.INVALID_ARGUMENT: (
            M6UpgradeExecutionLedgerV3FailureCode.INVALID_ARGUMENT
        ),
        M6UpgradeExecutionLedgerFailureCode.SCOPE_NOT_FOUND: (
            M6UpgradeExecutionLedgerV3FailureCode.SCOPE_NOT_FOUND
        ),
        M6UpgradeExecutionLedgerFailureCode.SCOPE_CONFLICT: (
            M6UpgradeExecutionLedgerV3FailureCode.SCOPE_CONFLICT
        ),
        M6UpgradeExecutionLedgerFailureCode.SCOPE_MISMATCH: (
            M6UpgradeExecutionLedgerV3FailureCode.SCOPE_MISMATCH
        ),
        M6UpgradeExecutionLedgerFailureCode.LEDGER_VERSION_UNSUPPORTED: (
            M6UpgradeExecutionLedgerV3FailureCode.LEDGER_VERSION_UNSUPPORTED
        ),
        M6UpgradeExecutionLedgerFailureCode.PHYSICAL_ARTIFACT_REJECTED: (
            M6UpgradeExecutionLedgerV3FailureCode.PHYSICAL_ARTIFACT_REJECTED
        ),
        M6UpgradeExecutionLedgerFailureCode.PHYSICAL_ARTIFACT_CONFLICT: (
            M6UpgradeExecutionLedgerV3FailureCode.PHYSICAL_ARTIFACT_REJECTED
        ),
        M6UpgradeExecutionLedgerFailureCode.SAMPLE_CONFLICT: (
            M6UpgradeExecutionLedgerV3FailureCode.SAMPLE_CONFLICT
        ),
        M6UpgradeExecutionLedgerFailureCode.SAMPLE_OUT_OF_ORDER: (
            M6UpgradeExecutionLedgerV3FailureCode.SAMPLE_OUT_OF_ORDER
        ),
        M6UpgradeExecutionLedgerFailureCode.LEDGER_SEALED: (
            M6UpgradeExecutionLedgerV3FailureCode.LEDGER_SEALED
        ),
        M6UpgradeExecutionLedgerFailureCode.LEDGER_INCOMPLETE: (
            M6UpgradeExecutionLedgerV3FailureCode.LEDGER_INCOMPLETE
        ),
        M6UpgradeExecutionLedgerFailureCode.LEDGER_NOT_SEALED: (
            M6UpgradeExecutionLedgerV3FailureCode.LEDGER_NOT_SEALED
        ),
        M6UpgradeExecutionLedgerFailureCode.DOCUMENT_TOO_LARGE: (
            M6UpgradeExecutionLedgerV3FailureCode.DOCUMENT_TOO_LARGE
        ),
        M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID: (
            M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID
        ),
        M6UpgradeExecutionLedgerFailureCode.SQLITE_REJECTED: (
            M6UpgradeExecutionLedgerV3FailureCode.STORAGE_REJECTED
        ),
    }
    translated = mapping.get(error.reason_code)
    if translated is not None:
        raise _error(translated) from error
    raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID) from error


def _translate_commitment_error(error: M6UpgradePendingSampleCommitmentError) -> NoReturn:
    mapping = {
        M6UpgradePendingSampleCommitmentFailureCode.INVALID_ARGUMENT: (
            M6UpgradeExecutionLedgerV3FailureCode.INVALID_ARGUMENT
        ),
        M6UpgradePendingSampleCommitmentFailureCode.SCOPE_NOT_FOUND: (
            M6UpgradeExecutionLedgerV3FailureCode.SCOPE_NOT_FOUND
        ),
        M6UpgradePendingSampleCommitmentFailureCode.SCOPE_MISMATCH: (
            M6UpgradeExecutionLedgerV3FailureCode.SCOPE_MISMATCH
        ),
        M6UpgradePendingSampleCommitmentFailureCode.OBSERVATION_NOT_FOUND: (
            M6UpgradeExecutionLedgerV3FailureCode.OBSERVATION_NOT_FOUND
        ),
        M6UpgradePendingSampleCommitmentFailureCode.COMMITMENT_NOT_FOUND: (
            M6UpgradeExecutionLedgerV3FailureCode.COMMITMENT_NOT_FOUND
        ),
        M6UpgradePendingSampleCommitmentFailureCode.COMMITMENT_CONFLICT: (
            M6UpgradeExecutionLedgerV3FailureCode.COMMITMENT_CONFLICT
        ),
        M6UpgradePendingSampleCommitmentFailureCode.COMMITMENT_OUT_OF_ORDER: (
            M6UpgradeExecutionLedgerV3FailureCode.SAMPLE_OUT_OF_ORDER
        ),
        M6UpgradePendingSampleCommitmentFailureCode.LEGACY_LEDGER_UNSUPPORTED: (
            M6UpgradeExecutionLedgerV3FailureCode.LEGACY_LEDGER_UNSUPPORTED
        ),
        M6UpgradePendingSampleCommitmentFailureCode.LEDGER_SEALED: (
            M6UpgradeExecutionLedgerV3FailureCode.LEDGER_SEALED
        ),
        M6UpgradePendingSampleCommitmentFailureCode.DOCUMENT_TOO_LARGE: (
            M6UpgradeExecutionLedgerV3FailureCode.DOCUMENT_TOO_LARGE
        ),
        M6UpgradePendingSampleCommitmentFailureCode.STORAGE_REJECTED: (
            M6UpgradeExecutionLedgerV3FailureCode.STORAGE_REJECTED
        ),
    }
    translated = mapping.get(error.reason_code)
    if translated is not None:
        raise _error(translated) from error
    raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID) from error


class SQLiteM6UpgradeExecutionLedgerV3Repository(SQLiteM6UpgradeExecutionLedgerRepository):
    """Consume exact V3 commitments and preserve all five restart states."""

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

    def _v3_fault(self, phase: str) -> None:
        if not isinstance(phase, str) or not phase:
            raise TypeError("M6 V3 ledger fault phase must be a non-empty string")
        if self._fault_injector is not None:
            self._fault_injector(f"m6_upgrade_execution_ledger_v3.{phase}")

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
        return _load_m6_upgrade_v3_state_from_connection_unchecked(
            self,
            connection,
            run_id,
            scope_id,
        )

    @staticmethod
    def _resume_from_state(state: M6SQLiteUpgradeV3State) -> M6UpgradeExecutionResumeV3:
        scope = state.stored_scope.authority
        sample_count = len(state.records)
        expected_count = len(scope.execution_dataset.entries)
        pending_observation = (
            state.observations[sample_count].authority
            if len(state.observations) > sample_count
            else None
        )
        pending_commitment = (
            state.commitments[sample_count].authority
            if len(state.commitments) > sample_count
            else None
        )
        if state.seal is not None:
            status = M6UpgradeExecutionLedgerV3Status.SEALED
        elif sample_count == expected_count:
            status = M6UpgradeExecutionLedgerV3Status.READY_TO_SEAL
        elif pending_commitment is not None:
            status = M6UpgradeExecutionLedgerV3Status.READY_FOR_LEDGER_APPEND
        elif pending_observation is not None:
            status = M6UpgradeExecutionLedgerV3Status.READY_FOR_COMMITMENT
        else:
            status = M6UpgradeExecutionLedgerV3Status.READY_FOR_OBSERVATION
        return M6UpgradeExecutionResumeV3(
            status=status,
            execution_scope=scope,
            committed_sample_count=sample_count,
            ledger_head_hash=state.ledger_head_hash,
            next_execution_entry=(
                scope.execution_dataset.entries[sample_count]
                if sample_count < expected_count
                else None
            ),
            pending_observation=pending_observation,
            pending_commitment=pending_commitment,
            seal=state.seal,
        )

    def _attempt_begin_execution(
        self,
        scope: M6UpgradeExecutionScopeAuthority,
    ) -> M6UpgradeExecutionScopeAuthority:
        try:
            return self._begin_execution_with_protocol(
                scope,
                protocol_version=M6UpgradeLedgerProtocolVersion.V3,
            )
        except M6UpgradeExecutionLedgerError as exc:
            _translate_base_error(exc)

    def begin_execution(
        self,
        scope: M6UpgradeExecutionScopeAuthority,
    ) -> M6UpgradeExecutionScopeAuthority:
        """Begin protocol V3 through a payload-free public facade."""

        failure = M6UpgradeExecutionLedgerV3FailureCode.STORAGE_REJECTED
        try:
            return self._attempt_begin_execution(scope)
        except M6UpgradeExecutionLedgerV3Error as error:
            failure = error.reason_code
        except Exception:
            pass
        del self, scope
        raise _error(failure) from None

    def _attempt_resume(
        self,
        run_id: str,
        execution_scope_authority_id: str,
    ) -> M6UpgradeExecutionResumeV3:
        controlled_run_id, controlled_scope_id = _require_lookup(
            run_id,
            execution_scope_authority_id,
        )
        try:
            with self._read() as connection:
                return self._resume_from_state(
                    self._load_state(connection, controlled_run_id, controlled_scope_id)
                )
        except M6UpgradeExecutionLedgerV3Error:
            raise
        except M6UpgradeExecutionLedgerError as exc:
            _translate_base_error(exc)
        except RepositoryIntegrityError as exc:
            raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID) from exc
        except sqlite3.DatabaseError as exc:
            raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID) from exc

    def resume(  # type: ignore[override]
        self,
        run_id: str,
        execution_scope_authority_id: str,
    ) -> M6UpgradeExecutionResumeV3:
        """Resume protocol V3 without retaining lookup or storage payloads."""

        failure = M6UpgradeExecutionLedgerV3FailureCode.STORAGE_REJECTED
        try:
            return self._attempt_resume(run_id, execution_scope_authority_id)
        except M6UpgradeExecutionLedgerV3Error as error:
            failure = error.reason_code
        except Exception:
            pass
        del self, run_id, execution_scope_authority_id
        raise _error(failure) from None

    def _verified_artifacts_v3(
        self,
        record: M6UpgradeSampleExecutionRecordV2,
    ) -> tuple[M6UpgradePhysicalArtifactRef, ...]:
        verifier = self._sample_artifact_verifier
        verify = getattr(verifier, "verify_m6_upgrade_sample_artifacts", None)
        if verifier is None or not callable(verify):
            raise _error(M6UpgradeExecutionLedgerV3FailureCode.PHYSICAL_ARTIFACT_REJECTED)
        expected = tuple(link.artifact for link in record.artifact_links)
        try:
            observed = verify(record)
        except Exception as exc:
            raise _error(M6UpgradeExecutionLedgerV3FailureCode.PHYSICAL_ARTIFACT_REJECTED) from exc
        if type(observed) is not tuple or len(observed) != len(expected):
            raise _error(M6UpgradeExecutionLedgerV3FailureCode.PHYSICAL_ARTIFACT_REJECTED)
        controlled: list[M6UpgradePhysicalArtifactRef] = []
        for artifact in observed:
            if type(artifact) is not M6UpgradePhysicalArtifactRef:
                raise _error(M6UpgradeExecutionLedgerV3FailureCode.PHYSICAL_ARTIFACT_REJECTED)
            try:
                canonical = M6UpgradePhysicalArtifactRef.model_validate(
                    artifact.model_dump(mode="json", exclude_computed_fields=True)
                )
            except (AttributeError, TypeError, ValueError, ValidationError) as exc:
                raise _error(
                    M6UpgradeExecutionLedgerV3FailureCode.PHYSICAL_ARTIFACT_REJECTED
                ) from exc
            if canonical != artifact:
                raise _error(M6UpgradeExecutionLedgerV3FailureCode.PHYSICAL_ARTIFACT_REJECTED)
            controlled.append(canonical)
        result = tuple(controlled)
        if result != expected:
            raise _error(M6UpgradeExecutionLedgerV3FailureCode.PHYSICAL_ARTIFACT_REJECTED)
        return result

    @staticmethod
    def _insert_record(
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

    def _attempt_append_committed_sample(
        self,
        commitment: M6UpgradePendingSampleCommitmentAuthority,
    ) -> M6UpgradeSampleExecutionRecordV2:
        if (
            type(commitment) is not M6UpgradePendingSampleCommitmentAuthority
            or type(commitment.sample_execution_record) is not M6UpgradeSampleExecutionRecordV2
        ):
            raise _error(M6UpgradeExecutionLedgerV3FailureCode.INVALID_ARGUMENT)
        try:
            controlled = canonical_pending_sample_commitment(commitment)
            controlled_documents = pending_sample_commitment_documents(controlled)
        except M6UpgradePendingSampleCommitmentError as exc:
            _translate_commitment_error(exc)
        try:
            with self._immediate() as connection:
                state = self._load_state(
                    connection,
                    controlled.candidate_run_id,
                    controlled.execution_scope_authority_id,
                )
                sequence = controlled.ledger_sequence
                if sequence >= len(state.commitments):
                    if state.seal is not None:
                        raise _error(M6UpgradeExecutionLedgerV3FailureCode.LEDGER_SEALED)
                    raise _error(M6UpgradeExecutionLedgerV3FailureCode.COMMITMENT_NOT_FOUND)
                stored_commitment = state.commitments[sequence]
                if (
                    stored_commitment.authority != controlled
                    or stored_commitment.documents != controlled_documents
                ):
                    raise _error(M6UpgradeExecutionLedgerV3FailureCode.COMMITMENT_CONFLICT)
                record = stored_commitment.authority.sample_execution_record
                verified_artifacts = self._verified_artifacts_v3(record)
                if sequence < len(state.records):
                    if state.records[sequence] != record:
                        raise _error(M6UpgradeExecutionLedgerV3FailureCode.SAMPLE_CONFLICT)
                    return state.records[sequence]
                if state.seal is not None:
                    raise _error(M6UpgradeExecutionLedgerV3FailureCode.LEDGER_SEALED)
                if (
                    sequence != len(state.records)
                    or len(state.observations) != sequence + 1
                    or len(state.commitments) != sequence + 1
                ):
                    raise _error(M6UpgradeExecutionLedgerV3FailureCode.SAMPLE_OUT_OF_ORDER)

                existing_by_key: dict[tuple[int, int, str, str], M6UpgradePhysicalArtifactRef] = {}
                existing_by_id: dict[str, M6UpgradePhysicalArtifactRef] = {}
                for prior_record in state.records:
                    for link in prior_record.artifact_links:
                        existing_by_key[link.artifact.physical_key] = link.artifact
                        existing_by_id[link.artifact.artifact_ref_id] = link.artifact
                for link, artifact in zip(record.artifact_links, verified_artifacts, strict=True):
                    if link.artifact != artifact:
                        raise _error(
                            M6UpgradeExecutionLedgerV3FailureCode.PHYSICAL_ARTIFACT_REJECTED
                        )
                    prior_by_key = existing_by_key.get(artifact.physical_key)
                    prior_by_id = existing_by_id.get(artifact.artifact_ref_id)
                    if (prior_by_key is not None and prior_by_key != artifact) or (
                        prior_by_id is not None and prior_by_id != artifact
                    ):
                        raise _error(
                            M6UpgradeExecutionLedgerV3FailureCode.PHYSICAL_ARTIFACT_REJECTED
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
                self._v3_fault("append_committed_sample.after_refs")
                for link in record.artifact_links:
                    self._append_link(
                        connection,
                        run_id=record.candidate_run_id,
                        execution_entry_id=record.execution_entry_id,
                        link=link,
                    )
                self._v3_fault("append_committed_sample.after_links")
                self._insert_record(connection, record, stored_commitment.documents)
                self._v3_fault("append_committed_sample.after_sample")
                readback = self._load_state(
                    connection,
                    controlled.candidate_run_id,
                    controlled.execution_scope_authority_id,
                )
                if (
                    len(readback.records) != len(state.records) + 1
                    or readback.records[-1] != record
                    or len(readback.observations) != len(readback.records)
                    or len(readback.commitments) != len(readback.records)
                ):
                    raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID)
                self._v3_fault("append_committed_sample.before_commit")
                return readback.records[-1]
        except M6UpgradeExecutionLedgerV3Error:
            raise
        except M6UpgradeExecutionLedgerError as exc:
            _translate_base_error(exc)
        except M6UpgradePendingSampleCommitmentError as exc:
            _translate_commitment_error(exc)
        except RepositoryIntegrityError as exc:
            raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID) from exc
        except ConcurrentModification as exc:
            raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORAGE_REJECTED) from exc
        except sqlite3.IntegrityError as exc:
            raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORAGE_REJECTED) from exc
        except sqlite3.DatabaseError as exc:
            raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORAGE_REJECTED) from exc

    def append_committed_sample(
        self,
        commitment: M6UpgradePendingSampleCommitmentAuthority,
    ) -> M6UpgradeSampleExecutionRecordV2:
        """Append one committed sample through a fresh typed failure boundary."""

        failure = M6UpgradeExecutionLedgerV3FailureCode.STORAGE_REJECTED
        try:
            return self._attempt_append_committed_sample(commitment)
        except M6UpgradeExecutionLedgerV3Error as error:
            failure = error.reason_code
        except Exception:
            pass
        del self, commitment
        raise _error(failure) from None

    @staticmethod
    def _insert_seal_v3(
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

    def _attempt_seal(
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
                state = self._load_state(connection, controlled_run_id, controlled_scope_id)
                if state.seal is not None:
                    return state.seal
                expected_count = len(state.stored_scope.authority.execution_dataset.entries)
                if not (
                    len(state.records)
                    == len(state.observations)
                    == len(state.commitments)
                    == expected_count
                ):
                    raise _error(M6UpgradeExecutionLedgerV3FailureCode.LEDGER_INCOMPLETE)
                try:
                    seal = M6UpgradeExecutionLedgerSealV2(
                        execution_scope=state.stored_scope.authority,
                        execution_scope_content_sha256=state.stored_scope.document_sha256,
                        execution_scope_size_bytes=state.stored_scope.size_bytes,
                        source_audit_head_sequence=state.current_audit_head_sequence,
                        source_audit_head_hash=state.current_audit_head_hash,
                        sample_executions=state.records,
                    )
                except (TypeError, ValueError, ValidationError) as exc:
                    raise _error(
                        M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID
                    ) from exc
                self._insert_seal_v3(connection, seal)
                self._v3_fault("seal.after_insert")
                readback = self._load_state(connection, controlled_run_id, controlled_scope_id)
                if readback.seal != seal:
                    raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID)
                self._v3_fault("seal.before_commit")
                return seal
        except M6UpgradeExecutionLedgerV3Error:
            raise
        except M6UpgradeExecutionLedgerError as exc:
            _translate_base_error(exc)
        except RepositoryIntegrityError as exc:
            raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID) from exc
        except ConcurrentModification as exc:
            raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORAGE_REJECTED) from exc
        except sqlite3.IntegrityError as exc:
            raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORAGE_REJECTED) from exc
        except sqlite3.DatabaseError as exc:
            raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORAGE_REJECTED) from exc

    def seal(
        self,
        run_id: str,
        execution_scope_authority_id: str,
    ) -> M6UpgradeExecutionLedgerSealV2:
        """Seal protocol V3 without retaining lower diagnostic chains."""

        failure = M6UpgradeExecutionLedgerV3FailureCode.STORAGE_REJECTED
        try:
            return self._attempt_seal(run_id, execution_scope_authority_id)
        except M6UpgradeExecutionLedgerV3Error as error:
            failure = error.reason_code
        except Exception:
            pass
        del self, run_id, execution_scope_authority_id
        raise _error(failure) from None

    def _attempt_load_sealed(
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
                state = self._load_state(connection, controlled_run_id, controlled_scope_id)
                if state.seal is None:
                    raise _error(M6UpgradeExecutionLedgerV3FailureCode.LEDGER_NOT_SEALED)
                return state.seal
        except M6UpgradeExecutionLedgerV3Error:
            raise
        except M6UpgradeExecutionLedgerError as exc:
            _translate_base_error(exc)
        except RepositoryIntegrityError as exc:
            raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID) from exc
        except sqlite3.DatabaseError as exc:
            raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID) from exc

    def load_sealed(
        self,
        run_id: str,
        execution_scope_authority_id: str,
    ) -> M6UpgradeExecutionLedgerSealV2:
        """Load Seal V2 through a fresh protocol-V3 failure boundary."""

        failure = M6UpgradeExecutionLedgerV3FailureCode.STORAGE_REJECTED
        try:
            return self._attempt_load_sealed(run_id, execution_scope_authority_id)
        except M6UpgradeExecutionLedgerV3Error as error:
            failure = error.reason_code
        except Exception:
            pass
        del self, run_id, execution_scope_authority_id
        raise _error(failure) from None


def _attempt_load_m6_upgrade_v3_state_from_connection(
    repository: SQLiteM6UpgradeExecutionLedgerV3Repository,
    connection: M6SQLiteReadSession,
    run_id: str,
    scope_id: str,
) -> M6SQLiteUpgradeV3State:
    """Load a complete V3 state without owning the caller's transaction."""

    if not isinstance(repository, SQLiteM6UpgradeExecutionLedgerV3Repository):
        raise _error(M6UpgradeExecutionLedgerV3FailureCode.INVALID_ARGUMENT)
    if not is_m6_sqlite_read_session(connection):
        raise _error(M6UpgradeExecutionLedgerV3FailureCode.INVALID_ARGUMENT)
    controlled_run_id, controlled_scope_id = _require_lookup(run_id, scope_id)
    try:
        if not connection.in_transaction:
            raise _error(M6UpgradeExecutionLedgerV3FailureCode.INVALID_ARGUMENT)
    except sqlite3.Error as exc:
        raise _error(M6UpgradeExecutionLedgerV3FailureCode.INVALID_ARGUMENT) from exc
    try:
        state = repository._load_state(
            connection,
            controlled_run_id,
            controlled_scope_id,
        )
        if not connection.in_transaction:
            raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORAGE_REJECTED)
        return state
    except M6UpgradeExecutionLedgerV3Error:
        raise
    except M6UpgradeExecutionLedgerError as exc:
        _translate_base_error(exc)
    except RepositoryIntegrityError as exc:
        raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID) from exc
    except sqlite3.DatabaseError as exc:
        raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORAGE_REJECTED) from exc


def load_m6_upgrade_v3_state_from_connection(
    repository: SQLiteM6UpgradeExecutionLedgerV3Repository,
    connection: M6SQLiteReadSession,
    run_id: str,
    scope_id: str,
) -> M6SQLiteUpgradeV3State:
    """Load V3 state while publishing only a fresh typed public failure."""

    failure = M6UpgradeExecutionLedgerV3FailureCode.STORAGE_REJECTED
    try:
        return _attempt_load_m6_upgrade_v3_state_from_connection(
            repository,
            connection,
            run_id,
            scope_id,
        )
    except M6UpgradeExecutionLedgerV3Error as error:
        failure = error.reason_code
    except Exception:
        pass
    del repository, connection, run_id, scope_id
    raise _error(failure) from None


__all__ = [
    "M6SQLiteUpgradeV3State",
    "SQLiteM6UpgradeExecutionLedgerV3Repository",
    "load_m6_upgrade_v3_state_from_connection",
]
