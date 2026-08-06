"""Fail-closed SQLite decoder for observation-backed M6 ledger V2 authorities."""

from __future__ import annotations

import sqlite3
from typing import NoReturn

from pydantic import ValidationError

from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6_UPGRADE_LEDGER_GENESIS_HASH,
    MAX_M6_UPGRADE_LEDGER_LINKS,
    MAX_M6_UPGRADE_LEDGER_LINKS_PER_SAMPLE,
    M6UpgradeExecutionLedgerSealV2,
    M6UpgradeSampleArtifactLink,
    M6UpgradeSampleExecutionRecordV2,
)
from labcourt.ports.m6_upgrade_execution_ledger import (
    M6UpgradeExecutionLedgerError,
    M6UpgradeExecutionLedgerFailureCode,
)
from labcourt.ports.m6_upgrade_execution_ledger_v2 import (
    M6UpgradeExecutionLedgerV2Error,
    M6UpgradeExecutionLedgerV2FailureCode,
)

from ._sqlite_m6_upgrade_execution_ledger_codec import (
    _LINK_JOIN_SQL,
    MAX_M6_UPGRADE_LEDGER_PREFIX_BYTES,
    MAX_M6_UPGRADE_LINK_BYTES,
    MAX_M6_UPGRADE_LINK_INVENTORY_BYTES,
    MAX_M6_UPGRADE_RECORD_BYTES,
    MAX_M6_UPGRADE_REF_BYTES,
    MAX_M6_UPGRADE_REF_INVENTORY_BYTES,
    MAX_M6_UPGRADE_SEAL_BYTES,
    M6UpgradeLedgerProtocolVersion,
    StoredM6UpgradeLedgerProtocol,
    StoredM6UpgradeScope,
    _link_from_joined_row,
    _load_link_groups,
    _parse_contract_document,
    _preflight_stored_inventory,
    ledger_protocol_from_connection,
)
from ._sqlite_read_session import SQLiteReadSession
from .sqlite_repository import (
    RepositoryIntegrityError,
    _row_int,
    _row_optional_int,
    _row_optional_str,
    _row_str,
)


def _error(
    code: M6UpgradeExecutionLedgerV2FailureCode,
) -> M6UpgradeExecutionLedgerV2Error:
    return M6UpgradeExecutionLedgerV2Error(code)


def _translate_v1_error(error: M6UpgradeExecutionLedgerError) -> NoReturn:
    if error.reason_code == M6UpgradeExecutionLedgerFailureCode.DOCUMENT_TOO_LARGE:
        raise _error(M6UpgradeExecutionLedgerV2FailureCode.DOCUMENT_TOO_LARGE) from error
    raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID) from error


def _require_v2_protocol(
    connection: SQLiteReadSession,
    run_id: str,
    *,
    execution_scope_authority_id: str | None = None,
) -> StoredM6UpgradeLedgerProtocol:
    try:
        protocol = ledger_protocol_from_connection(connection, run_id)
    except RepositoryIntegrityError as exc:
        raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID) from exc
    if protocol is None:
        raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID)
    if (
        execution_scope_authority_id is not None
        and protocol.execution_scope_authority_id != execution_scope_authority_id
    ):
        raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID)
    if protocol.version == M6UpgradeLedgerProtocolVersion.V1:
        raise _error(M6UpgradeExecutionLedgerV2FailureCode.LEGACY_LEDGER_UNSUPPORTED)
    if protocol.version != M6UpgradeLedgerProtocolVersion.V2:
        raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID)
    return protocol


def _require_v2_record_version_columns(
    connection: SQLiteReadSession,
    *,
    where_sql: str,
    where_parameters: tuple[object, ...],
) -> None:
    row = connection.execute(
        f"""
        SELECT COUNT(*) AS invalid_count
        FROM m6_upgrade_sample_executions
        WHERE {where_sql}
          AND (
              record_schema_version IS NOT 'v2'
              OR observation_authority_id IS NULL
          )
        """,
        where_parameters,
    ).fetchone()
    try:
        if row is None or _row_int(row, "invalid_count") != 0:
            raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID)
    except M6UpgradeExecutionLedgerV2Error:
        raise
    except (IndexError, KeyError, TypeError, RepositoryIntegrityError) as exc:
        raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID) from exc


def _record_v2_from_row(
    row: sqlite3.Row,
    links: tuple[M6UpgradeSampleArtifactLink, ...],
    *,
    expected_run_id: str,
    expected_scope_id: str,
) -> M6UpgradeSampleExecutionRecordV2:
    try:
        if _row_str(row, "record_schema_version") != "v2":
            raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID)
        observation_authority_id = _row_str(row, "observation_authority_id")
        raw = _row_str(row, "record_json")
        try:
            record = _parse_contract_document(
                raw=raw,
                document_sha256=_row_str(row, "record_document_sha256"),
                claimed_size_bytes=_row_int(row, "record_size_bytes"),
                max_bytes=MAX_M6_UPGRADE_RECORD_BYTES,
                model_type=M6UpgradeSampleExecutionRecordV2,
            )
        except M6UpgradeExecutionLedgerError as exc:
            _translate_v1_error(exc)
        candidate_case = record.candidate_case
        observed = (
            _row_str(row, "run_id"),
            _row_str(row, "execution_scope_authority_id"),
            _row_int(row, "ledger_sequence"),
            _row_str(row, "previous_ledger_entry_hash"),
            _row_str(row, "command_id"),
            _row_str(row, "execution_dataset_snapshot_id"),
            _row_str(row, "execution_entry_id"),
            _row_str(row, "sample_id"),
            _row_str(row, "outcome"),
            _row_optional_str(row, "case_id"),
            _row_optional_int(row, "case_revision"),
            _row_optional_str(row, "case_document_sha256"),
            _row_optional_int(row, "case_audit_sequence"),
            _row_optional_str(row, "case_audit_entry_hash"),
            _row_int(row, "artifact_link_count"),
            _row_str(row, "artifact_link_inventory_root_sha256"),
            _row_str(row, "sample_execution_record_id"),
            observation_authority_id,
        )
        expected = (
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
            record.observation_authority_id,
        )
        if (
            observed != expected
            or record.candidate_run_id != expected_run_id
            or record.execution_scope_authority_id != expected_scope_id
            or record.artifact_links != links
        ):
            raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID)
        return record
    except M6UpgradeExecutionLedgerV2Error:
        raise
    except (IndexError, KeyError, TypeError, RepositoryIntegrityError) as exc:
        raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID) from exc


def _record_v2_from_connection(
    connection: SQLiteReadSession,
    run_id: str,
    execution_entry_id: str,
) -> M6UpgradeSampleExecutionRecordV2 | None:
    protocol = _require_v2_protocol(connection, run_id)
    _require_v2_record_version_columns(
        connection,
        where_sql="run_id = ? AND execution_entry_id = ?",
        where_parameters=(run_id, execution_entry_id),
    )
    try:
        record_budget = _preflight_stored_inventory(
            connection,
            table="m6_upgrade_sample_executions",
            size_column="record_size_bytes",
            json_column="record_json",
            where_sql="run_id = ? AND execution_entry_id = ?",
            where_parameters=(run_id, execution_entry_id),
            max_items=1,
            max_item_bytes=MAX_M6_UPGRADE_RECORD_BYTES,
            max_inventory_bytes=MAX_M6_UPGRADE_RECORD_BYTES,
        )
    except M6UpgradeExecutionLedgerError as exc:
        _translate_v1_error(exc)
    if record_budget.item_count == 0:
        return None
    row = connection.execute(
        """
        SELECT * FROM m6_upgrade_sample_executions
        WHERE run_id = ? AND execution_entry_id = ?
        """,
        (run_id, execution_entry_id),
    ).fetchone()
    if row is None:
        raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID)
    try:
        link_budget = _preflight_stored_inventory(
            connection,
            table="m6_upgrade_sample_artifact_links",
            size_column="link_size_bytes",
            json_column="link_json",
            where_sql="run_id = ? AND execution_entry_id = ?",
            where_parameters=(run_id, execution_entry_id),
            max_items=MAX_M6_UPGRADE_LEDGER_LINKS_PER_SAMPLE,
            max_item_bytes=MAX_M6_UPGRADE_LINK_BYTES,
            max_inventory_bytes=MAX_M6_UPGRADE_LINK_INVENTORY_BYTES,
        )
        ref_budget = _preflight_stored_inventory(
            connection,
            table=(
                "m6_upgrade_physical_artifact_refs AS ref "
                "JOIN m6_upgrade_sample_artifact_links AS link "
                "ON ref.run_id = link.run_id "
                "AND ref.artifact_ref_id = link.artifact_ref_id"
            ),
            size_column="ref.ref_size_bytes",
            json_column="ref.ref_json",
            where_sql="link.run_id = ? AND link.execution_entry_id = ?",
            where_parameters=(run_id, execution_entry_id),
            max_items=MAX_M6_UPGRADE_LEDGER_LINKS_PER_SAMPLE,
            max_item_bytes=MAX_M6_UPGRADE_REF_BYTES,
            max_inventory_bytes=MAX_M6_UPGRADE_REF_INVENTORY_BYTES,
        )
    except M6UpgradeExecutionLedgerError as exc:
        _translate_v1_error(exc)
    if ref_budget.item_count != link_budget.item_count:
        raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID)
    link_rows = connection.execute(
        _LINK_JOIN_SQL
        + " WHERE link.run_id = ? AND link.execution_entry_id = ? ORDER BY link.ordinal",
        (run_id, execution_entry_id),
    )
    links: list[M6UpgradeSampleArtifactLink] = []
    try:
        for link_row in link_rows:
            links.append(_link_from_joined_row(link_row))
    except M6UpgradeExecutionLedgerError as exc:
        _translate_v1_error(exc)
    if len(links) != link_budget.item_count:
        raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID)
    return _record_v2_from_row(
        row,
        tuple(links),
        expected_run_id=run_id,
        expected_scope_id=protocol.execution_scope_authority_id,
    )


def record_v2_from_connection(
    connection: SQLiteReadSession,
    run_id: str,
    execution_entry_id: str,
) -> M6UpgradeSampleExecutionRecordV2 | None:
    """Decode one exact V2 row after protocol and bounded-column preflight."""

    try:
        return _record_v2_from_connection(connection, run_id, execution_entry_id)
    except M6UpgradeExecutionLedgerV2Error:
        raise
    except M6UpgradeExecutionLedgerError as exc:
        _translate_v1_error(exc)
    except (
        IndexError,
        KeyError,
        TypeError,
        RepositoryIntegrityError,
        sqlite3.DatabaseError,
    ) as exc:
        raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID) from exc


def _records_v2_from_connection(
    connection: SQLiteReadSession,
    stored_scope: StoredM6UpgradeScope,
) -> tuple[M6UpgradeSampleExecutionRecordV2, ...]:
    scope = stored_scope.authority
    _require_v2_protocol(
        connection,
        scope.candidate_run_id,
        execution_scope_authority_id=scope.execution_scope_authority_id,
    )
    _require_v2_record_version_columns(
        connection,
        where_sql="run_id = ?",
        where_parameters=(scope.candidate_run_id,),
    )
    try:
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
    except M6UpgradeExecutionLedgerError as exc:
        _translate_v1_error(exc)

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
            raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID)
        stored_ref_ids.add(_row_str(ref_row, "artifact_ref_id"))
    if observed_ref_count != ref_budget.item_count or len(stored_ref_ids) != observed_ref_count:
        raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID)
    linked_ref_ids = {
        link.artifact.artifact_ref_id for links in link_groups.values() for link in links
    }
    if stored_ref_ids != linked_ref_ids:
        raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID)

    rows = connection.execute(
        """
        SELECT * FROM m6_upgrade_sample_executions
        WHERE run_id = ? ORDER BY ledger_sequence
        """,
        (scope.candidate_run_id,),
    )
    row_entry_ids: set[str] = set()
    records_list: list[M6UpgradeSampleExecutionRecordV2] = []
    for row in rows:
        execution_entry_id = _row_str(row, "execution_entry_id")
        row_entry_ids.add(execution_entry_id)
        records_list.append(
            _record_v2_from_row(
                row,
                link_groups.get(execution_entry_id, ()),
                expected_run_id=scope.candidate_run_id,
                expected_scope_id=scope.execution_scope_authority_id,
            )
        )
    if len(records_list) != record_budget.item_count or len(row_entry_ids) != len(records_list):
        raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID)
    if set(link_groups) != row_entry_ids:
        raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID)

    records = tuple(records_list)
    previous = M6_UPGRADE_LEDGER_GENESIS_HASH
    for index, record in enumerate(records):
        if (
            record.ledger_sequence != index
            or record.previous_ledger_entry_hash != previous
            or record.execution_scope_authority_id != scope.execution_scope_authority_id
            or record.candidate_run_id != scope.candidate_run_id
            or record.command_id != scope.command.command_id
            or record.execution_dataset_snapshot_id
            != scope.execution_dataset.execution_dataset_snapshot_id
            or record.execution_entry != scope.execution_dataset.entries[index]
        ):
            raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID)
        previous = record.sample_execution_record_id
    return records


def records_v2_from_connection(
    connection: SQLiteReadSession,
    stored_scope: StoredM6UpgradeScope,
) -> tuple[M6UpgradeSampleExecutionRecordV2, ...]:
    """Decode the exact continuous V2 prefix and its complete linked ref closure."""

    try:
        return _records_v2_from_connection(connection, stored_scope)
    except M6UpgradeExecutionLedgerV2Error:
        raise
    except M6UpgradeExecutionLedgerError as exc:
        _translate_v1_error(exc)
    except (
        IndexError,
        KeyError,
        TypeError,
        RepositoryIntegrityError,
        sqlite3.DatabaseError,
    ) as exc:
        raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID) from exc


def _seal_v2_from_row(
    connection: SQLiteReadSession,
    row: sqlite3.Row,
    stored_scope: StoredM6UpgradeScope,
    records: tuple[M6UpgradeSampleExecutionRecordV2, ...],
) -> M6UpgradeExecutionLedgerSealV2:
    scope = stored_scope.authority
    _require_v2_protocol(
        connection,
        scope.candidate_run_id,
        execution_scope_authority_id=scope.execution_scope_authority_id,
    )
    try:
        if _row_str(row, "seal_schema_version") != "v2":
            raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID)
        if any(type(record) is not M6UpgradeSampleExecutionRecordV2 for record in records):
            raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID)
        claimed_size_bytes = _row_int(row, "size_bytes")
        if claimed_size_bytes > MAX_M6_UPGRADE_SEAL_BYTES:
            raise _error(M6UpgradeExecutionLedgerV2FailureCode.DOCUMENT_TOO_LARGE)
        raw = _row_str(row, "seal_json")
        try:
            seal = _parse_contract_document(
                raw=raw,
                document_sha256=_row_str(row, "document_sha256"),
                claimed_size_bytes=claimed_size_bytes,
                max_bytes=MAX_M6_UPGRADE_SEAL_BYTES,
                model_type=M6UpgradeExecutionLedgerSealV2,
            )
        except M6UpgradeExecutionLedgerError as exc:
            _translate_v1_error(exc)
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
        if type(seal) is not M6UpgradeExecutionLedgerSealV2 or observed != expected:
            raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID)
        if seal != rebuilt:
            raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID)
        return seal
    except M6UpgradeExecutionLedgerV2Error:
        raise
    except M6UpgradeExecutionLedgerError as exc:
        _translate_v1_error(exc)
    except (IndexError, KeyError, TypeError, ValueError, ValidationError) as exc:
        raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID) from exc


def seal_v2_from_row(
    connection: SQLiteReadSession,
    row: sqlite3.Row,
    stored_scope: StoredM6UpgradeScope,
    records: tuple[M6UpgradeSampleExecutionRecordV2, ...],
) -> M6UpgradeExecutionLedgerSealV2:
    """Decode and independently rebuild one exact V2 seal."""

    try:
        return _seal_v2_from_row(connection, row, stored_scope, records)
    except M6UpgradeExecutionLedgerV2Error:
        raise
    except M6UpgradeExecutionLedgerError as exc:
        _translate_v1_error(exc)
    except (
        IndexError,
        KeyError,
        TypeError,
        RepositoryIntegrityError,
        sqlite3.DatabaseError,
    ) as exc:
        raise _error(M6UpgradeExecutionLedgerV2FailureCode.STORED_AUTHORITY_INVALID) from exc


__all__ = [
    "record_v2_from_connection",
    "records_v2_from_connection",
    "seal_v2_from_row",
]
