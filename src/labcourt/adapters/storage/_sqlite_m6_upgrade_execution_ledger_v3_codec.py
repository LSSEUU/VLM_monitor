"""Single fail-closed SQLite state decoder for the M6 ledger protocol V3."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import NoReturn, cast

from pydantic import ValidationError

from labcourt.contracts.m6_replay_locked import M6LockedModelCallLayer
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6_UPGRADE_LEDGER_GENESIS_HASH,
    MAX_M6_UPGRADE_LEDGER_LINKS,
    MAX_M6_UPGRADE_LEDGER_LINKS_PER_SAMPLE,
    M6UpgradeExecutionLedgerSealV2,
    M6UpgradeSampleExecutionRecordV2,
)
from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeSampleExecutionObservationAuthorityV2,
    M6UpgradeSelectedCaseAuditAnchor,
)
from labcourt.contracts.m6_upgrade_pending_sample_commitment import (
    M6UpgradePendingSampleCommitmentAuthority,
)
from labcourt.contracts.m6_upgrade_physical import (
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactSource,
)
from labcourt.ports.m6_upgrade_execution_ledger import (
    M6UpgradeExecutionLedgerError,
    M6UpgradeExecutionLedgerFailureCode,
)
from labcourt.ports.m6_upgrade_execution_ledger_v2 import (
    M6UpgradeExecutionLedgerV2Error,
    M6UpgradeExecutionLedgerV2FailureCode,
)
from labcourt.ports.m6_upgrade_execution_ledger_v3 import (
    M6UpgradeExecutionLedgerV3Error,
    M6UpgradeExecutionLedgerV3FailureCode,
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
    MAX_M6_UPGRADE_LINK_BYTES,
    MAX_M6_UPGRADE_LINK_INVENTORY_BYTES,
    MAX_M6_UPGRADE_RECORD_BYTES,
    MAX_M6_UPGRADE_REF_BYTES,
    MAX_M6_UPGRADE_REF_INVENTORY_BYTES,
    MAX_M6_UPGRADE_SCOPE_BYTES,
    MAX_M6_UPGRADE_SEAL_BYTES,
    M6UpgradeLedgerProtocolVersion,
    StoredM6UpgradeScope,
    _load_link_groups,
    _parse_contract_document,
    _preflight_stored_inventory,
    ledger_protocol_from_connection,
    scope_from_row,
)
from ._sqlite_m6_upgrade_execution_ledger_v2_codec import (
    _record_v2_from_row,
    _require_v2_record_version_columns,
)
from ._sqlite_m6_upgrade_execution_observation_codec import (
    MAX_M6_UPGRADE_OBSERVATION_BYTES,
    MAX_M6_UPGRADE_OBSERVATION_INVENTORY_BYTES,
    StoredM6UpgradeExecutionObservationV2,
    observation_v2_from_connection,
)
from ._sqlite_m6_upgrade_pending_sample_commitment_codec import (
    MAX_M6_UPGRADE_PENDING_COMMITMENT_BYTES,
    MAX_M6_UPGRADE_PENDING_COMMITMENT_INVENTORY_BYTES,
    MAX_M6_UPGRADE_PENDING_RECORD_BYTES,
    MAX_M6_UPGRADE_PENDING_RECORD_INVENTORY_BYTES,
    StoredM6UpgradePendingSampleCommitment,
    pending_sample_commitment_from_connection,
)
from ._sqlite_m6_upgrade_v2_prefix import (
    validate_m6_upgrade_v2_prefix_identity_closure,
)
from ._sqlite_read_session import SQLiteReadSession
from .sqlite_m6_upgrade_execution_ledger import SQLiteM6UpgradeExecutionLedgerRepository
from .sqlite_repository import (
    RepositoryIntegrityError,
    _row_int,
    _row_optional_str,
    _row_str,
)


def _error(
    code: M6UpgradeExecutionLedgerV3FailureCode,
) -> M6UpgradeExecutionLedgerV3Error:
    return M6UpgradeExecutionLedgerV3Error(code)


def _translate_base_error(error: M6UpgradeExecutionLedgerError) -> NoReturn:
    if error.reason_code == M6UpgradeExecutionLedgerFailureCode.DOCUMENT_TOO_LARGE:
        raise _error(M6UpgradeExecutionLedgerV3FailureCode.DOCUMENT_TOO_LARGE) from error
    raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID) from error


def _translate_v2_codec_error(error: M6UpgradeExecutionLedgerV2Error) -> NoReturn:
    if error.reason_code == M6UpgradeExecutionLedgerV2FailureCode.DOCUMENT_TOO_LARGE:
        raise _error(M6UpgradeExecutionLedgerV3FailureCode.DOCUMENT_TOO_LARGE) from error
    raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID) from error


def _translate_observation_error(error: M6UpgradeExecutionObservationError) -> NoReturn:
    if error.reason_code == M6UpgradeExecutionObservationFailureCode.DOCUMENT_TOO_LARGE:
        raise _error(M6UpgradeExecutionLedgerV3FailureCode.DOCUMENT_TOO_LARGE) from error
    raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID) from error


def _translate_commitment_error(error: M6UpgradePendingSampleCommitmentError) -> NoReturn:
    if error.reason_code == M6UpgradePendingSampleCommitmentFailureCode.DOCUMENT_TOO_LARGE:
        raise _error(M6UpgradeExecutionLedgerV3FailureCode.DOCUMENT_TOO_LARGE) from error
    raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID) from error


@dataclass(frozen=True, slots=True)
class M6SQLiteUpgradeV3State:
    """One completely validated durable V3 recovery state."""

    stored_scope: StoredM6UpgradeScope
    records: tuple[M6UpgradeSampleExecutionRecordV2, ...]
    observations: tuple[StoredM6UpgradeExecutionObservationV2, ...]
    commitments: tuple[StoredM6UpgradePendingSampleCommitment, ...]
    current_audit_head_sequence: int
    current_audit_head_hash: str
    seal: M6UpgradeExecutionLedgerSealV2 | None

    @property
    def ledger_head_hash(self) -> str:
        if not self.records:
            return M6_UPGRADE_LEDGER_GENESIS_HASH
        return self.records[-1].sample_execution_record_id


def stored_scope_v3_from_connection(
    connection: SQLiteReadSession,
    run_id: str,
    execution_scope_authority_id: str,
) -> StoredM6UpgradeScope:
    """Load the exact V3 scope after inspecting only its small protocol marker."""

    try:
        protocol = ledger_protocol_from_connection(connection, run_id)
    except RepositoryIntegrityError as exc:
        raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID) from exc
    if protocol is None:
        raise _error(M6UpgradeExecutionLedgerV3FailureCode.SCOPE_NOT_FOUND)
    if protocol.execution_scope_authority_id != execution_scope_authority_id:
        raise _error(M6UpgradeExecutionLedgerV3FailureCode.SCOPE_MISMATCH)
    if protocol.version in {
        M6UpgradeLedgerProtocolVersion.V1,
        M6UpgradeLedgerProtocolVersion.V2,
    }:
        raise _error(M6UpgradeExecutionLedgerV3FailureCode.LEGACY_LEDGER_UNSUPPORTED)
    if protocol.version is not M6UpgradeLedgerProtocolVersion.V3:
        raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID)
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
        _translate_base_error(exc)
    if budget.item_count != 1:
        raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID)
    row = connection.execute(
        "SELECT * FROM m6_upgrade_execution_scopes WHERE run_id = ?",
        (run_id,),
    ).fetchone()
    if row is None:
        raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID)
    try:
        stored = scope_from_row(row)
    except M6UpgradeExecutionLedgerError as exc:
        _translate_base_error(exc)
    if stored.authority.execution_scope_authority_id != execution_scope_authority_id:
        raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID)
    return stored


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
            raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID)
        count = _row_int(row, "item_count")
    except M6UpgradeExecutionLedgerV3Error:
        raise
    except (IndexError, KeyError, TypeError, RepositoryIntegrityError) as exc:
        raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID) from exc
    if count > limit:
        raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID)
    return count


def _records_v3_from_connection(
    connection: SQLiteReadSession,
    stored_scope: StoredM6UpgradeScope,
) -> tuple[tuple[M6UpgradeSampleExecutionRecordV2, ...], int]:
    scope = stored_scope.authority
    try:
        _require_v2_record_version_columns(
            connection,
            where_sql="run_id = ?",
            where_parameters=(scope.candidate_run_id,),
        )
        record_budget = _preflight_stored_inventory(
            connection,
            table="m6_upgrade_sample_executions",
            size_column="record_size_bytes",
            json_column="record_json",
            where_sql="run_id = ?",
            where_parameters=(scope.candidate_run_id,),
            max_items=len(scope.execution_dataset.entries),
            max_item_bytes=MAX_M6_UPGRADE_RECORD_BYTES,
            max_inventory_bytes=MAX_M6_UPGRADE_LEDGER_PREFIX_BYTES,
            prefix_bytes=stored_scope.size_bytes,
        )
        link_budget = _preflight_stored_inventory(
            connection,
            table="m6_upgrade_sample_artifact_links",
            size_column="link_size_bytes",
            json_column="link_json",
            where_sql="run_id = ?",
            where_parameters=(scope.candidate_run_id,),
            max_items=MAX_M6_UPGRADE_LEDGER_LINKS,
            max_item_bytes=MAX_M6_UPGRADE_LINK_BYTES,
            max_inventory_bytes=MAX_M6_UPGRADE_LINK_INVENTORY_BYTES,
        )
        ref_budget = _preflight_stored_inventory(
            connection,
            table="m6_upgrade_physical_artifact_refs",
            size_column="ref_size_bytes",
            json_column="ref_json",
            where_sql="run_id = ?",
            where_parameters=(scope.candidate_run_id,),
            max_items=MAX_M6_UPGRADE_LEDGER_LINKS,
            max_item_bytes=MAX_M6_UPGRADE_REF_BYTES,
            max_inventory_bytes=MAX_M6_UPGRADE_REF_INVENTORY_BYTES,
        )
        link_groups = _load_link_groups(
            connection,
            scope.candidate_run_id,
            expected_item_count=link_budget.item_count,
        )
    except M6UpgradeExecutionLedgerV2Error as exc:
        _translate_v2_codec_error(exc)
    except M6UpgradeExecutionLedgerError as exc:
        _translate_base_error(exc)

    ref_rows = connection.execute(
        """
        SELECT artifact_ref_id, execution_scope_authority_id
        FROM m6_upgrade_physical_artifact_refs
        WHERE run_id = ? ORDER BY artifact_ref_id
        """,
        (scope.candidate_run_id,),
    )
    stored_ref_ids: set[str] = set()
    observed_ref_count = 0
    for ref_row in ref_rows:
        observed_ref_count += 1
        if _row_str(ref_row, "execution_scope_authority_id") != (
            scope.execution_scope_authority_id
        ):
            raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID)
        stored_ref_ids.add(_row_str(ref_row, "artifact_ref_id"))
    if observed_ref_count != ref_budget.item_count or len(stored_ref_ids) != observed_ref_count:
        raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID)
    linked_ref_ids = {
        link.artifact.artifact_ref_id for links in link_groups.values() for link in links
    }
    if stored_ref_ids != linked_ref_ids:
        raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID)

    rows = connection.execute(
        """
        SELECT * FROM m6_upgrade_sample_executions
        WHERE run_id = ? ORDER BY ledger_sequence
        """,
        (scope.candidate_run_id,),
    )
    records_list: list[M6UpgradeSampleExecutionRecordV2] = []
    row_entry_ids: set[str] = set()
    try:
        for row in rows:
            execution_entry_id = _row_str(row, "execution_entry_id")
            row_entry_ids.add(execution_entry_id)
            record = _record_v2_from_row(
                row,
                link_groups.get(execution_entry_id, ()),
                expected_run_id=scope.candidate_run_id,
                expected_scope_id=scope.execution_scope_authority_id,
            )
            if type(record) is not M6UpgradeSampleExecutionRecordV2:
                raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID)
            records_list.append(record)
    except M6UpgradeExecutionLedgerV2Error as exc:
        _translate_v2_codec_error(exc)
    if len(records_list) != record_budget.item_count or len(row_entry_ids) != len(records_list):
        raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID)
    if set(link_groups) != row_entry_ids:
        raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID)

    records = tuple(records_list)
    previous = M6_UPGRADE_LEDGER_GENESIS_HASH
    for sequence, record in enumerate(records):
        if (
            record.ledger_sequence != sequence
            or record.previous_ledger_entry_hash != previous
            or record.execution_scope_authority_id != scope.execution_scope_authority_id
            or record.candidate_run_id != scope.candidate_run_id
            or record.command_id != scope.command.command_id
            or record.execution_dataset_snapshot_id
            != scope.execution_dataset.execution_dataset_snapshot_id
            or record.execution_entry != scope.execution_dataset.entries[sequence]
        ):
            raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID)
        previous = record.sample_execution_record_id
    return records, record_budget.canonical_bytes


def _seal_row_v3(
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
        raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID) from exc
    if size_bytes > MAX_M6_UPGRADE_SEAL_BYTES or actual_size_bytes > MAX_M6_UPGRADE_SEAL_BYTES:
        raise _error(M6UpgradeExecutionLedgerV3FailureCode.DOCUMENT_TOO_LARGE)
    if version != "v2" or json_type != "text" or size_bytes < 1 or size_bytes != actual_size_bytes:
        raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID)
    row = connection.execute(
        "SELECT * FROM m6_upgrade_execution_ledger_seals WHERE run_id = ?",
        (run_id,),
    ).fetchone()
    if row is None:
        raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID)
    return cast(sqlite3.Row, row)


def seal_v2_for_v3_from_row(
    row: sqlite3.Row,
    stored_scope: StoredM6UpgradeScope,
    records: tuple[M6UpgradeSampleExecutionRecordV2, ...],
) -> M6UpgradeExecutionLedgerSealV2:
    """Decode unchanged Seal-V2 bytes without dispatching through protocol V2."""

    scope = stored_scope.authority
    try:
        if _row_str(row, "seal_schema_version") != "v2" or any(
            type(record) is not M6UpgradeSampleExecutionRecordV2 for record in records
        ):
            raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID)
        try:
            seal = _parse_contract_document(
                raw=_row_str(row, "seal_json"),
                document_sha256=_row_str(row, "document_sha256"),
                claimed_size_bytes=_row_int(row, "size_bytes"),
                max_bytes=MAX_M6_UPGRADE_SEAL_BYTES,
                model_type=M6UpgradeExecutionLedgerSealV2,
            )
        except M6UpgradeExecutionLedgerError as exc:
            _translate_base_error(exc)
        rebuilt = M6UpgradeExecutionLedgerSealV2(
            execution_scope=scope,
            execution_scope_content_sha256=stored_scope.document_sha256,
            execution_scope_size_bytes=stored_scope.size_bytes,
            source_audit_head_sequence=_row_int(row, "source_audit_head_sequence"),
            source_audit_head_hash=_row_str(row, "source_audit_head_hash"),
            sample_executions=records,
        )
        observed = (
            _row_str(row, "run_id"),
            _row_str(row, "execution_scope_authority_id"),
            _row_str(row, "execution_scope_document_sha256"),
            _row_int(row, "execution_scope_size_bytes"),
            _row_int(row, "source_audit_head_sequence"),
            _row_str(row, "source_audit_head_hash"),
            _row_int(row, "sample_execution_count"),
            _row_str(row, "sample_execution_inventory_root_sha256"),
            _row_int(row, "artifact_link_count"),
            _row_str(row, "artifact_link_inventory_root_sha256"),
            _row_int(row, "candidate_case_count"),
            _row_str(row, "candidate_case_inventory_root_sha256"),
            _row_int(row, "ledger_preseal_sequence"),
            _row_str(row, "ledger_preseal_hash"),
            _row_int(row, "ledger_head_sequence"),
            _row_str(row, "ledger_seal_authority_id"),
        )
        expected = (
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
        )
        if (
            type(seal) is not M6UpgradeExecutionLedgerSealV2
            or observed != expected
            or seal != rebuilt
        ):
            raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID)
        return seal
    except M6UpgradeExecutionLedgerV3Error:
        raise
    except (IndexError, KeyError, TypeError, ValueError, ValidationError) as exc:
        raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID) from exc


def observation_v2_closes_record_v2(
    observation: M6UpgradeSampleExecutionObservationAuthorityV2,
    record: M6UpgradeSampleExecutionRecordV2,
) -> bool:
    """Return whether two exact V3 wire authorities describe one sample."""

    if (
        type(observation) is not M6UpgradeSampleExecutionObservationAuthorityV2
        or type(record) is not M6UpgradeSampleExecutionRecordV2
        or observation.observation_authority_id != record.observation_authority_id
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


def _validate_observation_scope(
    observation: M6UpgradeSampleExecutionObservationAuthorityV2,
    stored_scope: StoredM6UpgradeScope,
    sequence: int,
) -> None:
    scope = stored_scope.authority
    entries = scope.execution_dataset.entries
    if (
        type(observation) is not M6UpgradeSampleExecutionObservationAuthorityV2
        or sequence >= len(entries)
        or observation.execution_scope_authority_id != scope.execution_scope_authority_id
        or observation.candidate_run_id != scope.candidate_run_id
        or observation.command_id != scope.command.command_id
        or observation.execution_dataset_snapshot_id
        != scope.execution_dataset.execution_dataset_snapshot_id
        or observation.ledger_sequence != sequence
        or observation.execution_entry != entries[sequence]
    ):
        raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID)


def _validate_case_audit_anchors(
    connection: SQLiteReadSession,
    stored_scope: StoredM6UpgradeScope,
    observations: tuple[StoredM6UpgradeExecutionObservationV2, ...],
    *,
    current_audit_head_sequence: int,
) -> None:
    scope = stored_scope.authority
    start_sequence = scope.execution_start_audit_head_sequence
    for stored in observations:
        observation = stored.authority
        binding = observation.candidate_case
        anchor = observation.selected_case_audit_anchor
        if binding is None:
            if anchor is not None:
                raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID)
            continue
        if (
            type(anchor) is not M6UpgradeSelectedCaseAuditAnchor
            or binding.case_audit_sequence <= start_sequence
            or binding.case_audit_sequence > current_audit_head_sequence
        ):
            raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID)
        row = connection.execute(
            """
            SELECT
                version.document_sha256 AS case_document_sha256,
                version.audit_sequence AS case_audit_sequence,
                audit.manifest_id AS audit_manifest_id,
                audit.action AS audit_action,
                audit.object_kind AS audit_object_kind,
                audit.object_id AS audit_object_id,
                audit.after_sha256 AS audit_after_sha256,
                audit.entry_hash AS audit_entry_hash
            FROM case_versions AS version
            JOIN audit_entries AS audit
              ON audit.run_id = version.run_id
             AND audit.sequence = version.audit_sequence
            WHERE version.run_id = ?
              AND version.case_id = ?
              AND version.revision = ?
            """,
            (scope.candidate_run_id, binding.case_id, binding.case_revision),
        ).fetchone()
        if row is None:
            raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID)
        observed = (
            _row_str(row, "case_document_sha256"),
            _row_int(row, "case_audit_sequence"),
            _row_str(row, "audit_manifest_id"),
            _row_str(row, "audit_action"),
            _row_str(row, "audit_object_kind"),
            _row_str(row, "audit_object_id"),
            _row_optional_str(row, "audit_after_sha256"),
            _row_str(row, "audit_entry_hash"),
        )
        expected = (
            binding.case_document_sha256,
            binding.case_audit_sequence,
            scope.candidate_manifest.manifest_id,
            anchor.action.value,
            anchor.object_ref.kind.value,
            anchor.object_ref.artifact_id,
            binding.case_document_sha256,
            binding.case_audit_entry_hash,
        )
        if observed != expected:
            raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID)


def _load_m6_upgrade_v3_state(
    repository: SQLiteM6UpgradeExecutionLedgerRepository,
    connection: SQLiteReadSession,
    stored_scope: StoredM6UpgradeScope,
) -> M6SQLiteUpgradeV3State:
    scope = stored_scope.authority
    expected_count = len(scope.execution_dataset.entries)
    records, record_bytes = _records_v3_from_connection(connection, stored_scope)
    try:
        current_head_sequence, current_head_hash = repository._validated_run_audit_head(
            connection,
            stored_scope,
        )
    except M6UpgradeExecutionLedgerError as exc:
        _translate_base_error(exc)

    observation_count = _bounded_count(
        connection,
        table="m6_upgrade_sample_execution_observations",
        run_id=scope.candidate_run_id,
        limit=expected_count + 1,
    )
    commitment_count = _bounded_count(
        connection,
        table="m6_upgrade_pending_sample_commitments",
        run_id=scope.candidate_run_id,
        limit=expected_count + 1,
    )
    seal_count = _bounded_count(
        connection,
        table="m6_upgrade_execution_ledger_seals",
        run_id=scope.candidate_run_id,
        limit=1,
    )
    sample_count = len(records)
    if seal_count:
        valid_topology = sample_count == observation_count == commitment_count == expected_count
    elif sample_count == expected_count:
        valid_topology = observation_count == commitment_count == expected_count
    else:
        valid_topology = sample_count < expected_count and (
            observation_count,
            commitment_count,
        ) in {
            (sample_count, sample_count),
            (sample_count + 1, sample_count),
            (sample_count + 1, sample_count + 1),
        }
    if not valid_topology:
        raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID)

    try:
        observation_budget = _preflight_stored_inventory(
            connection,
            table="m6_upgrade_sample_execution_observations",
            size_column="size_bytes",
            json_column="observation_json",
            where_sql="run_id = ?",
            where_parameters=(scope.candidate_run_id,),
            max_items=expected_count,
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
            where_parameters=(scope.candidate_run_id,),
            max_items=expected_count,
            max_item_bytes=MAX_M6_UPGRADE_PENDING_RECORD_BYTES,
            max_inventory_bytes=MAX_M6_UPGRADE_PENDING_RECORD_INVENTORY_BYTES,
        )
    except M6UpgradeExecutionLedgerError as exc:
        _translate_base_error(exc)
    if (
        observation_budget.item_count != observation_count
        or commitment_budget.item_count != commitment_count
        or commitment_record_budget.item_count != commitment_count
    ):
        raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID)

    observations_list: list[StoredM6UpgradeExecutionObservationV2] = []
    for sequence in range(observation_count):
        try:
            stored_observation = observation_v2_from_connection(
                connection,
                scope.candidate_run_id,
                sequence,
            )
        except M6UpgradeExecutionObservationError as exc:
            _translate_observation_error(exc)
        if stored_observation is None:
            raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID)
        _validate_observation_scope(stored_observation.authority, stored_scope, sequence)
        observations_list.append(stored_observation)
    observations = tuple(observations_list)

    child_limit = MAX_M6_UPGRADE_LEDGER_LINKS + MAX_M6_UPGRADE_LEDGER_LINKS_PER_SAMPLE
    non_model_child_count = _bounded_count(
        connection,
        table="m6_upgrade_observed_non_model_artifacts",
        run_id=scope.candidate_run_id,
        limit=child_limit,
    )
    model_child_count = _bounded_count(
        connection,
        table="m6_upgrade_observed_model_calls",
        run_id=scope.candidate_run_id,
        limit=child_limit,
    )
    if non_model_child_count != sum(len(item.authority.artifacts) for item in observations):
        raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID)
    if model_child_count != sum(len(item.authority.model_calls) for item in observations):
        raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID)

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
        if (
            stored_commitment is None
            or type(stored_commitment.authority) is not M6UpgradePendingSampleCommitmentAuthority
            or type(stored_commitment.authority.sample_execution_record)
            is not M6UpgradeSampleExecutionRecordV2
        ):
            raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID)
        commitments_list.append(stored_commitment)
    commitments = tuple(commitments_list)

    for sequence, record in enumerate(records):
        if commitments[
            sequence
        ].authority.sample_execution_record != record or not observation_v2_closes_record_v2(
            observations[sequence].authority, record
        ):
            raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID)
    if observation_count > sample_count and commitment_count > sample_count:
        pending_record = commitments[sample_count].authority.sample_execution_record
        expected_previous = (
            records[-1].sample_execution_record_id if records else M6_UPGRADE_LEDGER_GENESIS_HASH
        )
        if (
            pending_record.previous_ledger_entry_hash != expected_previous
            or not observation_v2_closes_record_v2(
                observations[sample_count].authority,
                pending_record,
            )
        ):
            raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID)

    complete_prefix = records + (
        (commitments[sample_count].authority.sample_execution_record,)
        if commitment_count > sample_count
        else ()
    )
    try:
        validate_m6_upgrade_v2_prefix_identity_closure(complete_prefix)
    except ValueError as exc:
        raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID) from exc
    pending_record_bytes = (
        commitments[sample_count].documents.sample_execution_record_size_bytes
        if commitment_count > sample_count
        else 0
    )
    if (
        stored_scope.size_bytes + record_bytes + pending_record_bytes
        > MAX_M6_UPGRADE_LEDGER_PREFIX_BYTES
    ):
        raise _error(M6UpgradeExecutionLedgerV3FailureCode.DOCUMENT_TOO_LARGE)
    _validate_case_audit_anchors(
        connection,
        stored_scope,
        observations,
        current_audit_head_sequence=current_head_sequence,
    )

    seal: M6UpgradeExecutionLedgerSealV2 | None = None
    if seal_count:
        seal_row = _seal_row_v3(connection, scope.candidate_run_id)
        if seal_row is None:
            raise _error(M6UpgradeExecutionLedgerV3FailureCode.STORED_AUTHORITY_INVALID)
        seal = seal_v2_for_v3_from_row(seal_row, stored_scope, records)
        try:
            repository._validate_seal_audit_cut(
                connection,
                stored_scope,
                seal,
                current_head_sequence=current_head_sequence,
            )
        except M6UpgradeExecutionLedgerError as exc:
            _translate_base_error(exc)
    return M6SQLiteUpgradeV3State(
        stored_scope=stored_scope,
        records=records,
        observations=observations,
        commitments=commitments,
        current_audit_head_sequence=current_head_sequence,
        current_audit_head_hash=current_head_hash,
        seal=seal,
    )


def _load_m6_upgrade_v3_state_from_connection_unchecked(
    repository: SQLiteM6UpgradeExecutionLedgerRepository,
    connection: SQLiteReadSession,
    run_id: str,
    execution_scope_authority_id: str,
) -> M6SQLiteUpgradeV3State:
    """Internal decoder; public callers must use the guarded repository facade."""

    stored_scope = stored_scope_v3_from_connection(
        connection,
        run_id,
        execution_scope_authority_id,
    )
    return _load_m6_upgrade_v3_state(repository, connection, stored_scope)


__all__ = [
    "M6SQLiteUpgradeV3State",
    "observation_v2_closes_record_v2",
    "seal_v2_for_v3_from_row",
    "stored_scope_v3_from_connection",
]
