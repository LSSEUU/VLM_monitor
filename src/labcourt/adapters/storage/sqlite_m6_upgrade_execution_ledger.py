"""Guarded SQLite persistence for the append-only M6 upgrade execution ledger."""

from __future__ import annotations

import sqlite3

from pydantic import ValidationError

from labcourt.contracts.audit import AUDIT_GENESIS_HASH
from labcourt.contracts.m6_upgrade_execution_ledger import (
    MAX_M6_UPGRADE_LEDGER_LINKS,
    M6UpgradeExecutionLedgerSeal,
    M6UpgradeExecutionScopeAuthority,
    M6UpgradeSampleArtifactLink,
    M6UpgradeSampleExecutionRecord,
    M6UpgradeSampleExecutionRecordV2,
)
from labcourt.contracts.m6_upgrade_physical import M6UpgradePhysicalArtifactRef
from labcourt.contracts.references import require_reference_token
from labcourt.exceptions import ConcurrentModification, ContractViolation
from labcourt.ports.m6_upgrade_execution_ledger import (
    M6UpgradeExecutionLedgerError,
    M6UpgradeExecutionLedgerFailureCode,
    M6UpgradeExecutionLedgerStatus,
    M6UpgradeExecutionResume,
    M6UpgradeSampleArtifactVerifier,
)

from ._sqlite_m6_upgrade_execution_ledger_codec import (
    MAX_M6_UPGRADE_LINK_BYTES,
    MAX_M6_UPGRADE_RECORD_BYTES,
    MAX_M6_UPGRADE_REF_BYTES,
    MAX_M6_UPGRADE_SCOPE_BYTES,
    MAX_M6_UPGRADE_SEAL_BYTES,
    M6UpgradeLedgerProtocolVersion,
    StoredM6UpgradeScope,
    artifact_from_row,
    canonical_model,
    contract_document,
    ledger_protocol_from_connection,
    record_from_connection,
    records_from_connection,
    scope_from_row,
    seal_from_row,
)
from ._sqlite_read_session import SQLiteReadSession
from .sqlite_m5_repository import SQLiteM5Repository
from .sqlite_repository import (
    MigrationIntegrityError,
    RepositoryIntegrityError,
    _row_int,
    _row_str,
)
from .sqlite_schema import m6_upgrade_ledger_installed


def _error(code: M6UpgradeExecutionLedgerFailureCode) -> M6UpgradeExecutionLedgerError:
    return M6UpgradeExecutionLedgerError(code)


def _require_lookup(run_id: object, execution_scope_authority_id: object) -> tuple[str, str]:
    try:
        if not isinstance(run_id, str):
            raise TypeError
        controlled_run_id = require_reference_token(run_id, "M6 upgrade ledger run_id")
    except (TypeError, ValueError) as exc:
        raise _error(M6UpgradeExecutionLedgerFailureCode.INVALID_ARGUMENT) from exc
    if (
        not isinstance(execution_scope_authority_id, str)
        or len(execution_scope_authority_id) != 64
        or any(character not in "0123456789abcdef" for character in execution_scope_authority_id)
    ):
        raise _error(M6UpgradeExecutionLedgerFailureCode.INVALID_ARGUMENT)
    return controlled_run_id, execution_scope_authority_id


class SQLiteM6UpgradeExecutionLedgerRepository(SQLiteM5Repository):
    """One scope, ordered sample chain, and repository-derived seal per candidate run."""

    def _connection(self) -> sqlite3.Connection:
        connection = super()._connection()
        try:
            connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_M6_UPGRADE_SEAL_BYTES)
            if not m6_upgrade_ledger_installed(connection):
                raise MigrationIntegrityError(
                    "SQLite M6 upgrade ledger layout is incomplete; apply migrations 0010--0013"
                )
            return connection
        except BaseException:
            connection.close()
            raise

    def _ledger_fault(self, phase: str) -> None:
        if not isinstance(phase, str) or not phase:
            raise TypeError("M6 ledger fault phase must be a non-empty string")
        if self._fault_injector is not None:
            self._fault_injector(f"m6_upgrade_execution_ledger.{phase}")

    def _stored_scope(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        execution_scope_authority_id: str,
    ) -> StoredM6UpgradeScope:
        protocol = ledger_protocol_from_connection(connection, run_id)
        if protocol is None:
            raise _error(M6UpgradeExecutionLedgerFailureCode.SCOPE_NOT_FOUND)
        if protocol.execution_scope_authority_id != execution_scope_authority_id:
            raise _error(M6UpgradeExecutionLedgerFailureCode.SCOPE_MISMATCH)
        if protocol.version != M6UpgradeLedgerProtocolVersion.V1:
            raise _error(M6UpgradeExecutionLedgerFailureCode.LEDGER_VERSION_UNSUPPORTED)
        row = connection.execute(
            "SELECT * FROM m6_upgrade_execution_scopes WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        if row is None:
            raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID)
        stored = scope_from_row(row)
        if stored.authority.execution_scope_authority_id != protocol.execution_scope_authority_id:
            raise _error(M6UpgradeExecutionLedgerFailureCode.SCOPE_MISMATCH)
        return stored

    def _stored_scope_for_begin(
        self,
        connection: SQLiteReadSession,
        run_id: str,
        execution_scope_authority_id: str,
    ) -> StoredM6UpgradeScope:
        """Load one begin readback; protocol-specific repositories may preflight it."""

        row = connection.execute(
            "SELECT * FROM m6_upgrade_execution_scopes WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        if row is None:
            raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID)
        stored = scope_from_row(row)
        if stored.authority.execution_scope_authority_id != execution_scope_authority_id:
            raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID)
        return stored

    def _validated_run_audit_head(
        self,
        connection: SQLiteReadSession,
        stored_scope: StoredM6UpgradeScope,
    ) -> tuple[int, str]:
        scope = stored_scope.authority
        count_row = connection.execute(
            """
            SELECT COUNT(*) AS item_count FROM (
                SELECT 1 FROM audit_entries WHERE run_id = ? LIMIT ?
            )
            """,
            (scope.candidate_run_id, MAX_M6_UPGRADE_LEDGER_LINKS + 1),
        ).fetchone()
        if count_row is None or _row_int(count_row, "item_count") > MAX_M6_UPGRADE_LEDGER_LINKS:
            raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID)
        inventory = connection.execute(
            """
            SELECT
                COALESCE(SUM(
                    CASE WHEN typeof(entry_json) = 'text'
                              AND length(CAST(entry_json AS BLOB)) <= ?
                         THEN length(CAST(entry_json AS BLOB)) ELSE 0 END
                ), 0) AS total_size_bytes,
                COALESCE(SUM(
                    CASE WHEN typeof(entry_json) <> 'text' THEN 1 ELSE 0 END
                ), 0) AS invalid_count,
                COALESCE(SUM(
                    CASE WHEN typeof(entry_json) = 'text'
                              AND length(CAST(entry_json AS BLOB)) > ?
                         THEN 1 ELSE 0 END
                ), 0) AS oversized_count
            FROM audit_entries WHERE run_id = ?
            """,
            (
                MAX_M6_UPGRADE_SEAL_BYTES,
                MAX_M6_UPGRADE_SEAL_BYTES,
                scope.candidate_run_id,
            ),
        ).fetchone()
        if inventory is None or _row_int(inventory, "invalid_count") != 0:
            raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID)
        if (
            _row_int(inventory, "oversized_count") != 0
            or _row_int(inventory, "total_size_bytes") > MAX_M6_UPGRADE_SEAL_BYTES
        ):
            raise _error(M6UpgradeExecutionLedgerFailureCode.DOCUMENT_TOO_LARGE)
        try:
            head = self._validated_head(connection, scope.candidate_run_id)
        except ContractViolation as exc:
            raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID) from exc
        if (
            head.run_id != scope.candidate_run_id
            or head.manifest_id != scope.candidate_manifest.manifest_id
            or head.run_revision != head.sequence + 1
        ):
            raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID)
        return head.sequence, head.entry_hash

    @staticmethod
    def _validate_seal_audit_cut(
        connection: SQLiteReadSession,
        stored_scope: StoredM6UpgradeScope,
        seal: M6UpgradeExecutionLedgerSeal,
        *,
        current_head_sequence: int,
    ) -> None:
        if seal.source_audit_head_sequence == -1:
            if seal.source_audit_head_hash != AUDIT_GENESIS_HASH:
                raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID)
            return
        if seal.source_audit_head_sequence > current_head_sequence:
            raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID)
        row = connection.execute(
            """
            SELECT manifest_id, entry_hash FROM audit_entries
            WHERE run_id = ? AND sequence = ?
            """,
            (seal.candidate_run_id, seal.source_audit_head_sequence),
        ).fetchone()
        if (
            row is None
            or _row_str(row, "manifest_id") != stored_scope.authority.candidate_manifest.manifest_id
            or _row_str(row, "entry_hash") != seal.source_audit_head_hash
        ):
            raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID)

    def begin_execution(
        self,
        scope: M6UpgradeExecutionScopeAuthority,
    ) -> M6UpgradeExecutionScopeAuthority:
        return self._begin_execution_with_protocol(
            scope,
            protocol_version=M6UpgradeLedgerProtocolVersion.V1,
        )

    def _begin_execution_with_protocol(
        self,
        scope: M6UpgradeExecutionScopeAuthority,
        *,
        protocol_version: M6UpgradeLedgerProtocolVersion,
    ) -> M6UpgradeExecutionScopeAuthority:
        controlled = canonical_model(scope, M6UpgradeExecutionScopeAuthority)
        document, document_sha256, size_bytes = contract_document(
            controlled,
            max_bytes=MAX_M6_UPGRADE_SCOPE_BYTES,
        )
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
                        raise _error(M6UpgradeExecutionLedgerFailureCode.SCOPE_CONFLICT)
                    if protocol.version != protocol_version:
                        raise _error(M6UpgradeExecutionLedgerFailureCode.LEDGER_VERSION_UNSUPPORTED)
                    observed = self._stored_scope_for_begin(
                        connection,
                        controlled.candidate_run_id,
                        controlled.execution_scope_authority_id,
                    ).authority
                    if observed != controlled:
                        raise _error(M6UpgradeExecutionLedgerFailureCode.SCOPE_CONFLICT)
                    return observed
                connection.execute(
                    """
                    INSERT INTO m6_upgrade_execution_ledger_protocols(
                        run_id, execution_scope_authority_id, protocol_version
                    ) VALUES (?, ?, ?)
                    """,
                    (
                        controlled.candidate_run_id,
                        controlled.execution_scope_authority_id,
                        protocol_version.value,
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
                self._ledger_fault("begin_execution.after_insert")
                observed_protocol = ledger_protocol_from_connection(
                    connection,
                    controlled.candidate_run_id,
                )
                if (
                    observed_protocol is None
                    or observed_protocol.execution_scope_authority_id
                    != controlled.execution_scope_authority_id
                    or observed_protocol.version != protocol_version
                ):
                    raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID)
                readback = self._stored_scope_for_begin(
                    connection,
                    controlled.candidate_run_id,
                    controlled.execution_scope_authority_id,
                ).authority
                if readback != controlled:
                    raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID)
                self._ledger_fault("begin_execution.before_commit")
                return readback
        except M6UpgradeExecutionLedgerError:
            raise
        except RepositoryIntegrityError as exc:
            raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID) from exc
        except ConcurrentModification as exc:
            raise _error(M6UpgradeExecutionLedgerFailureCode.SQLITE_REJECTED) from exc
        except sqlite3.IntegrityError as exc:
            raise _error(M6UpgradeExecutionLedgerFailureCode.SQLITE_REJECTED) from exc
        except sqlite3.DatabaseError as exc:
            raise _error(M6UpgradeExecutionLedgerFailureCode.SQLITE_REJECTED) from exc

    def resume(
        self,
        run_id: str,
        execution_scope_authority_id: str,
    ) -> M6UpgradeExecutionResume:
        controlled_run_id, controlled_scope_id = _require_lookup(
            run_id,
            execution_scope_authority_id,
        )
        try:
            with self._read() as connection:
                stored_scope = self._stored_scope(
                    connection,
                    controlled_run_id,
                    controlled_scope_id,
                )
                records = records_from_connection(connection, stored_scope)
                current_head_sequence, _current_head_hash = self._validated_run_audit_head(
                    connection,
                    stored_scope,
                )
                seal_row = connection.execute(
                    "SELECT * FROM m6_upgrade_execution_ledger_seals WHERE run_id = ?",
                    (controlled_run_id,),
                ).fetchone()
                ledger_head_hash = (
                    records[-1].sample_execution_record_id if records else AUDIT_GENESIS_HASH
                )
                if seal_row is not None:
                    seal = seal_from_row(seal_row, stored_scope, records)
                    self._validate_seal_audit_cut(
                        connection,
                        stored_scope,
                        seal,
                        current_head_sequence=current_head_sequence,
                    )
                    return M6UpgradeExecutionResume(
                        status=M6UpgradeExecutionLedgerStatus.SEALED,
                        execution_scope=stored_scope.authority,
                        committed_sample_count=len(records),
                        ledger_head_hash=ledger_head_hash,
                        next_execution_entry=None,
                        seal=seal,
                    )
                entries = stored_scope.authority.execution_dataset.entries
                if len(records) == len(entries):
                    return M6UpgradeExecutionResume(
                        status=M6UpgradeExecutionLedgerStatus.READY_TO_SEAL,
                        execution_scope=stored_scope.authority,
                        committed_sample_count=len(records),
                        ledger_head_hash=ledger_head_hash,
                        next_execution_entry=None,
                    )
                return M6UpgradeExecutionResume(
                    status=M6UpgradeExecutionLedgerStatus.ACTIVE,
                    execution_scope=stored_scope.authority,
                    committed_sample_count=len(records),
                    ledger_head_hash=ledger_head_hash,
                    next_execution_entry=entries[len(records)],
                )
        except M6UpgradeExecutionLedgerError:
            raise
        except RepositoryIntegrityError as exc:
            raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID) from exc
        except sqlite3.DatabaseError as exc:
            raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID) from exc

    @staticmethod
    def _verified_artifacts(
        record: M6UpgradeSampleExecutionRecord,
        verifier: M6UpgradeSampleArtifactVerifier | None,
    ) -> tuple[M6UpgradePhysicalArtifactRef, ...]:
        if verifier is None:
            raise _error(M6UpgradeExecutionLedgerFailureCode.VERIFIER_REQUIRED)
        verify = getattr(verifier, "verify_m6_upgrade_sample_artifacts", None)
        if not callable(verify):
            raise _error(M6UpgradeExecutionLedgerFailureCode.VERIFIER_INVALID)
        expected = tuple(link.artifact for link in record.artifact_links)
        try:
            observed = verify(record)
            if type(observed) is not tuple or len(observed) != len(expected):
                raise _error(M6UpgradeExecutionLedgerFailureCode.PHYSICAL_ARTIFACT_REJECTED)
            controlled_observed = tuple(
                canonical_model(
                    artifact,
                    M6UpgradePhysicalArtifactRef,
                    failure_code=(M6UpgradeExecutionLedgerFailureCode.PHYSICAL_ARTIFACT_REJECTED),
                )
                for artifact in observed
            )
        except M6UpgradeExecutionLedgerError:
            raise
        except Exception as exc:
            raise _error(M6UpgradeExecutionLedgerFailureCode.PHYSICAL_ARTIFACT_REJECTED) from exc
        if controlled_observed != expected:
            raise _error(M6UpgradeExecutionLedgerFailureCode.PHYSICAL_ARTIFACT_REJECTED)
        return controlled_observed

    @staticmethod
    def _append_artifact(
        connection: sqlite3.Connection,
        *,
        run_id: str,
        execution_scope_authority_id: str,
        artifact: M6UpgradePhysicalArtifactRef,
    ) -> None:
        rows = connection.execute(
            """
            SELECT * FROM m6_upgrade_physical_artifact_refs
            WHERE run_id = ? AND (
                artifact_ref_id = ?
                OR (
                    source = ? AND kind = ? AND artifact_id = ?
                    AND container_id IS ?
                )
            )
            """,
            (
                run_id,
                artifact.artifact_ref_id,
                artifact.source.value,
                artifact.kind.value,
                artifact.artifact_id,
                artifact.container_id,
            ),
        ).fetchall()
        if len(rows) > 1:
            raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID)
        if rows:
            stored = artifact_from_row(rows[0])
            if (
                stored.execution_scope_authority_id != execution_scope_authority_id
                or stored.authority != artifact
            ):
                raise _error(M6UpgradeExecutionLedgerFailureCode.PHYSICAL_ARTIFACT_CONFLICT)
            return
        document, document_sha256, size_bytes = contract_document(
            artifact,
            max_bytes=MAX_M6_UPGRADE_REF_BYTES,
        )
        connection.execute(
            """
            INSERT INTO m6_upgrade_physical_artifact_refs(
                run_id, execution_scope_authority_id,
                artifact_ref_id, source, kind, artifact_id, container_id,
                artifact_document_sha256, artifact_content_sha256,
                artifact_size_bytes, ref_json, ref_document_sha256, ref_size_bytes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                execution_scope_authority_id,
                artifact.artifact_ref_id,
                artifact.source.value,
                artifact.kind.value,
                artifact.artifact_id,
                artifact.container_id,
                artifact.document_sha256,
                artifact.content_sha256,
                artifact.size_bytes,
                document,
                document_sha256,
                size_bytes,
            ),
        )
        readback_row = connection.execute(
            """
            SELECT * FROM m6_upgrade_physical_artifact_refs
            WHERE run_id = ? AND artifact_ref_id = ?
            """,
            (run_id, artifact.artifact_ref_id),
        ).fetchone()
        if readback_row is None or artifact_from_row(readback_row).authority != artifact:
            raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID)

    @staticmethod
    def _append_link(
        connection: sqlite3.Connection,
        *,
        run_id: str,
        execution_entry_id: str,
        link: M6UpgradeSampleArtifactLink,
    ) -> None:
        document, document_sha256, size_bytes = contract_document(
            link,
            max_bytes=MAX_M6_UPGRADE_LINK_BYTES,
        )
        connection.execute(
            """
            INSERT INTO m6_upgrade_sample_artifact_links(
                run_id, execution_entry_id, ordinal, usage,
                artifact_ref_id, artifact_link_id,
                link_json, link_document_sha256, link_size_bytes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                execution_entry_id,
                link.ordinal,
                link.usage.value,
                link.artifact.artifact_ref_id,
                link.artifact_link_id,
                document,
                document_sha256,
                size_bytes,
            ),
        )

    @staticmethod
    def _append_record_row(
        connection: sqlite3.Connection,
        record: M6UpgradeSampleExecutionRecord,
    ) -> None:
        document, document_sha256, size_bytes = contract_document(
            record,
            max_bytes=MAX_M6_UPGRADE_RECORD_BYTES,
        )
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
                document,
                document_sha256,
                size_bytes,
                "v1",
                None,
            ),
        )

    def append_sample(
        self,
        record: M6UpgradeSampleExecutionRecord,
        verifier: M6UpgradeSampleArtifactVerifier | None = None,
    ) -> M6UpgradeSampleExecutionRecord:
        if isinstance(record, M6UpgradeSampleExecutionRecordV2):
            raise _error(M6UpgradeExecutionLedgerFailureCode.LEDGER_VERSION_UNSUPPORTED)
        controlled = canonical_model(record, M6UpgradeSampleExecutionRecord)
        try:
            with self._immediate() as connection:
                stored_scope = self._stored_scope(
                    connection,
                    controlled.candidate_run_id,
                    controlled.execution_scope_authority_id,
                )
                self._validated_run_audit_head(connection, stored_scope)
                if (
                    connection.execute(
                        "SELECT 1 FROM m6_upgrade_execution_ledger_seals WHERE run_id = ?",
                        (controlled.candidate_run_id,),
                    ).fetchone()
                    is not None
                ):
                    raise _error(M6UpgradeExecutionLedgerFailureCode.LEDGER_SEALED)
                scope = stored_scope.authority
                if (
                    controlled.command_id != scope.command.command_id
                    or controlled.execution_dataset_snapshot_id
                    != scope.execution_dataset.execution_dataset_snapshot_id
                ):
                    raise _error(M6UpgradeExecutionLedgerFailureCode.SCOPE_MISMATCH)
                persisted_records = records_from_connection(connection, stored_scope)
                collisions = connection.execute(
                    """
                    SELECT execution_entry_id FROM m6_upgrade_sample_executions
                    WHERE run_id = ? AND (
                        ledger_sequence = ? OR execution_entry_id = ?
                        OR sample_id = ? OR sample_execution_record_id = ?
                    )
                    """,
                    (
                        controlled.candidate_run_id,
                        controlled.ledger_sequence,
                        controlled.execution_entry_id,
                        controlled.sample_id,
                        controlled.sample_execution_record_id,
                    ),
                ).fetchall()
                if collisions:
                    if (
                        len(collisions) == 1
                        and _row_str(collisions[0], "execution_entry_id")
                        == controlled.execution_entry_id
                    ):
                        observed = record_from_connection(
                            connection,
                            controlled.candidate_run_id,
                            controlled.execution_entry_id,
                        )
                        if observed == controlled:
                            return observed
                    raise _error(M6UpgradeExecutionLedgerFailureCode.SAMPLE_CONFLICT)

                record_count = len(persisted_records)
                expected_previous = (
                    persisted_records[-1].sample_execution_record_id
                    if persisted_records
                    else AUDIT_GENESIS_HASH
                )
                entries = scope.execution_dataset.entries
                if (
                    controlled.ledger_sequence != record_count
                    or record_count >= len(entries)
                    or controlled.previous_ledger_entry_hash != expected_previous
                    or controlled.execution_entry != entries[record_count]
                ):
                    raise _error(M6UpgradeExecutionLedgerFailureCode.SAMPLE_OUT_OF_ORDER)

                verified_artifacts = self._verified_artifacts(controlled, verifier)
                for link, artifact in zip(
                    controlled.artifact_links,
                    verified_artifacts,
                    strict=True,
                ):
                    if link.artifact != artifact:
                        raise _error(M6UpgradeExecutionLedgerFailureCode.PHYSICAL_ARTIFACT_REJECTED)
                    self._append_artifact(
                        connection,
                        run_id=controlled.candidate_run_id,
                        execution_scope_authority_id=(controlled.execution_scope_authority_id),
                        artifact=artifact,
                    )
                self._ledger_fault("append_sample.after_refs")
                for link in controlled.artifact_links:
                    self._append_link(
                        connection,
                        run_id=controlled.candidate_run_id,
                        execution_entry_id=controlled.execution_entry_id,
                        link=link,
                    )
                self._ledger_fault("append_sample.after_links")
                self._append_record_row(connection, controlled)
                self._ledger_fault("append_sample.after_sample")
                readback = record_from_connection(
                    connection,
                    controlled.candidate_run_id,
                    controlled.execution_entry_id,
                )
                if readback != controlled:
                    raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID)
                self._ledger_fault("append_sample.before_commit")
                return readback
        except M6UpgradeExecutionLedgerError:
            raise
        except RepositoryIntegrityError as exc:
            raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID) from exc
        except sqlite3.IntegrityError as exc:
            raise _error(M6UpgradeExecutionLedgerFailureCode.SQLITE_REJECTED) from exc
        except sqlite3.DatabaseError as exc:
            raise _error(M6UpgradeExecutionLedgerFailureCode.SQLITE_REJECTED) from exc

    @staticmethod
    def _insert_seal(
        connection: sqlite3.Connection,
        seal: M6UpgradeExecutionLedgerSeal,
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
                seal_json, document_sha256, size_bytes,
                seal_schema_version
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
                "v1",
            ),
        )

    def seal(
        self,
        run_id: str,
        execution_scope_authority_id: str,
    ) -> M6UpgradeExecutionLedgerSeal:
        controlled_run_id, controlled_scope_id = _require_lookup(
            run_id,
            execution_scope_authority_id,
        )
        try:
            with self._immediate() as connection:
                stored_scope = self._stored_scope(
                    connection,
                    controlled_run_id,
                    controlled_scope_id,
                )
                records = records_from_connection(connection, stored_scope)
                current_head_sequence, current_head_hash = self._validated_run_audit_head(
                    connection,
                    stored_scope,
                )
                existing = connection.execute(
                    "SELECT * FROM m6_upgrade_execution_ledger_seals WHERE run_id = ?",
                    (controlled_run_id,),
                ).fetchone()
                if existing is not None:
                    observed = seal_from_row(existing, stored_scope, records)
                    self._validate_seal_audit_cut(
                        connection,
                        stored_scope,
                        observed,
                        current_head_sequence=current_head_sequence,
                    )
                    return observed
                if len(records) != len(stored_scope.authority.execution_dataset.entries):
                    raise _error(M6UpgradeExecutionLedgerFailureCode.LEDGER_INCOMPLETE)
                try:
                    seal = M6UpgradeExecutionLedgerSeal(
                        execution_scope=stored_scope.authority,
                        execution_scope_content_sha256=stored_scope.document_sha256,
                        execution_scope_size_bytes=stored_scope.size_bytes,
                        source_audit_head_sequence=current_head_sequence,
                        source_audit_head_hash=current_head_hash,
                        sample_executions=records,
                    )
                except (TypeError, ValueError, ValidationError) as exc:
                    raise _error(M6UpgradeExecutionLedgerFailureCode.SQLITE_REJECTED) from exc
                self._insert_seal(connection, seal)
                self._ledger_fault("seal.after_insert")
                readback_row = connection.execute(
                    "SELECT * FROM m6_upgrade_execution_ledger_seals WHERE run_id = ?",
                    (controlled_run_id,),
                ).fetchone()
                if readback_row is None:
                    raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID)
                readback = seal_from_row(readback_row, stored_scope, records)
                if readback != seal:
                    raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID)
                self._ledger_fault("seal.before_commit")
                return readback
        except M6UpgradeExecutionLedgerError:
            raise
        except RepositoryIntegrityError as exc:
            raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID) from exc
        except sqlite3.IntegrityError as exc:
            raise _error(M6UpgradeExecutionLedgerFailureCode.SQLITE_REJECTED) from exc
        except sqlite3.DatabaseError as exc:
            raise _error(M6UpgradeExecutionLedgerFailureCode.SQLITE_REJECTED) from exc

    def load_sealed(
        self,
        run_id: str,
        execution_scope_authority_id: str,
    ) -> M6UpgradeExecutionLedgerSeal:
        controlled_run_id, controlled_scope_id = _require_lookup(
            run_id,
            execution_scope_authority_id,
        )
        try:
            with self._read() as connection:
                stored_scope = self._stored_scope(
                    connection,
                    controlled_run_id,
                    controlled_scope_id,
                )
                current_head_sequence, _current_head_hash = self._validated_run_audit_head(
                    connection,
                    stored_scope,
                )
                row = connection.execute(
                    "SELECT * FROM m6_upgrade_execution_ledger_seals WHERE run_id = ?",
                    (controlled_run_id,),
                ).fetchone()
                if row is None:
                    raise _error(M6UpgradeExecutionLedgerFailureCode.LEDGER_NOT_SEALED)
                records = records_from_connection(connection, stored_scope)
                seal = seal_from_row(row, stored_scope, records)
                self._validate_seal_audit_cut(
                    connection,
                    stored_scope,
                    seal,
                    current_head_sequence=current_head_sequence,
                )
                return seal
        except M6UpgradeExecutionLedgerError:
            raise
        except RepositoryIntegrityError as exc:
            raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID) from exc
        except sqlite3.DatabaseError as exc:
            raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID) from exc


__all__ = ["SQLiteM6UpgradeExecutionLedgerRepository"]
