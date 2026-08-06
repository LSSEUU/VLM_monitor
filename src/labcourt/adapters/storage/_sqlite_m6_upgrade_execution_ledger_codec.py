"""Canonical SQLite codec for the M6 upgrade execution ledger."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from enum import StrEnum
from typing import TypeVar

from pydantic import BaseModel, ValidationError

from labcourt.contracts.audit import AUDIT_GENESIS_HASH
from labcourt.contracts.m6_upgrade_execution_ledger import (
    MAX_M6_UPGRADE_LEDGER_DOCUMENT_BYTES,
    MAX_M6_UPGRADE_LEDGER_LINKS,
    MAX_M6_UPGRADE_LEDGER_LINKS_PER_SAMPLE,
    MAX_M6_UPGRADE_SAMPLE_EXECUTION_RECORD_DOCUMENT_BYTES,
    M6UpgradeExecutionLedgerSeal,
    M6UpgradeExecutionScopeAuthority,
    M6UpgradeSampleArtifactLink,
    M6UpgradeSampleExecutionRecord,
)
from labcourt.contracts.m6_upgrade_physical import M6UpgradePhysicalArtifactRef
from labcourt.ports.m6_upgrade_execution_ledger import (
    M6UpgradeExecutionLedgerError,
    M6UpgradeExecutionLedgerFailureCode,
)

from ._sqlite_read_session import SQLiteReadSession
from .sqlite_repository import (
    RepositoryIntegrityError,
    _document,
    _row_int,
    _row_optional_int,
    _row_optional_str,
    _row_str,
    _verify_contract_document,
)

MAX_M6_UPGRADE_SCOPE_BYTES = MAX_M6_UPGRADE_LEDGER_DOCUMENT_BYTES
MAX_M6_UPGRADE_SEAL_BYTES = MAX_M6_UPGRADE_LEDGER_DOCUMENT_BYTES
MAX_M6_UPGRADE_RECORD_BYTES = MAX_M6_UPGRADE_SAMPLE_EXECUTION_RECORD_DOCUMENT_BYTES
MAX_M6_UPGRADE_REF_BYTES = 1024 * 1024
MAX_M6_UPGRADE_LINK_BYTES = 1024 * 1024
MAX_M6_UPGRADE_LEDGER_PREFIX_BYTES = MAX_M6_UPGRADE_LEDGER_DOCUMENT_BYTES
MAX_M6_UPGRADE_LINK_INVENTORY_BYTES = MAX_M6_UPGRADE_LEDGER_DOCUMENT_BYTES
MAX_M6_UPGRADE_REF_INVENTORY_BYTES = MAX_M6_UPGRADE_LEDGER_DOCUMENT_BYTES

_ModelT = TypeVar("_ModelT", bound=BaseModel)


@dataclass(frozen=True, slots=True)
class StoredM6UpgradeScope:
    authority: M6UpgradeExecutionScopeAuthority
    document_sha256: str
    size_bytes: int


class M6UpgradeLedgerProtocolVersion(StrEnum):
    V1 = "v1"
    V2 = "v2"
    V3 = "v3"


@dataclass(frozen=True, slots=True)
class StoredM6UpgradeLedgerProtocol:
    execution_scope_authority_id: str
    version: M6UpgradeLedgerProtocolVersion


@dataclass(frozen=True, slots=True)
class StoredM6UpgradeArtifact:
    authority: M6UpgradePhysicalArtifactRef
    execution_scope_authority_id: str


@dataclass(frozen=True, slots=True)
class _StoredInventoryBudget:
    item_count: int
    canonical_bytes: int


def _error(code: M6UpgradeExecutionLedgerFailureCode) -> M6UpgradeExecutionLedgerError:
    return M6UpgradeExecutionLedgerError(code)


def _preflight_stored_inventory(
    connection: SQLiteReadSession,
    *,
    table: str,
    size_column: str,
    json_column: str,
    where_sql: str,
    where_parameters: tuple[object, ...],
    max_items: int,
    max_item_bytes: int,
    max_inventory_bytes: int,
    prefix_bytes: int = 0,
) -> _StoredInventoryBudget:
    """Bound and byte-check one stored JSON inventory before selecting any raw TEXT."""

    count_row = connection.execute(
        f"""
        SELECT COUNT(*) AS item_count
        FROM (
            SELECT 1 FROM {table}
            WHERE {where_sql}
            LIMIT ?
        )
        """,
        (*where_parameters, max_items + 1),
    ).fetchone()
    try:
        if count_row is None:
            raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID)
        item_count = _row_int(count_row, "item_count")
    except M6UpgradeExecutionLedgerError:
        raise
    except (IndexError, KeyError, TypeError, RepositoryIntegrityError) as exc:
        raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID) from exc
    if item_count > max_items:
        raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID)

    aggregate_row = connection.execute(
        f"""
        SELECT
            COALESCE(SUM(
                CASE
                    WHEN typeof({size_column}) = 'integer'
                     AND {size_column} BETWEEN 1 AND ?
                    THEN {size_column}
                    ELSE 0
                END
            ), 0) AS claimed_bytes,
            COALESCE(SUM(
                CASE
                    WHEN typeof({json_column}) = 'text'
                    THEN length(CAST({json_column} AS BLOB))
                    ELSE 0
                END
            ), 0) AS actual_bytes,
            COALESCE(SUM(
                CASE
                    WHEN typeof({size_column}) <> 'integer'
                      OR typeof({json_column}) <> 'text'
                      OR {size_column} < 1
                      OR length(CAST({json_column} AS BLOB)) < 1
                      OR {size_column} <> length(CAST({json_column} AS BLOB))
                    THEN 1
                    ELSE 0
                END
            ), 0) AS invalid_count,
            COALESCE(SUM(
                CASE
                    WHEN (typeof({size_column}) = 'integer' AND {size_column} > ?)
                      OR (typeof({json_column}) = 'text'
                          AND length(CAST({json_column} AS BLOB)) > ?)
                    THEN 1
                    ELSE 0
                END
            ), 0) AS oversized_count
        FROM {table}
        WHERE {where_sql}
        """,
        (max_item_bytes, max_item_bytes, max_item_bytes, *where_parameters),
    ).fetchone()
    try:
        if aggregate_row is None:
            raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID)
        claimed_bytes = _row_int(aggregate_row, "claimed_bytes")
        actual_bytes = _row_int(aggregate_row, "actual_bytes")
        invalid_count = _row_int(aggregate_row, "invalid_count")
        oversized_count = _row_int(aggregate_row, "oversized_count")
    except M6UpgradeExecutionLedgerError:
        raise
    except (IndexError, KeyError, TypeError, RepositoryIntegrityError) as exc:
        raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID) from exc
    if oversized_count:
        raise _error(M6UpgradeExecutionLedgerFailureCode.DOCUMENT_TOO_LARGE)
    if invalid_count or claimed_bytes != actual_bytes:
        raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID)
    if prefix_bytes > max_inventory_bytes or actual_bytes > max_inventory_bytes - prefix_bytes:
        raise _error(M6UpgradeExecutionLedgerFailureCode.DOCUMENT_TOO_LARGE)
    return _StoredInventoryBudget(item_count=item_count, canonical_bytes=actual_bytes)


def canonical_model(
    value: object,
    model_type: type[_ModelT],
    *,
    failure_code: M6UpgradeExecutionLedgerFailureCode = (
        M6UpgradeExecutionLedgerFailureCode.INVALID_ARGUMENT
    ),
) -> _ModelT:
    if not isinstance(value, model_type):
        raise _error(failure_code)
    try:
        controlled = model_type.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError) as exc:
        raise _error(failure_code) from exc
    if controlled != value:
        raise _error(failure_code)
    return controlled


def contract_document(value: BaseModel, *, max_bytes: int) -> tuple[str, str, int]:
    document, document_sha256 = _document(value)
    size_bytes = len(document.encode("utf-8"))
    if size_bytes > max_bytes:
        raise _error(M6UpgradeExecutionLedgerFailureCode.DOCUMENT_TOO_LARGE)
    return document, document_sha256, size_bytes


def _parse_contract_document(
    *,
    raw: str,
    document_sha256: str,
    claimed_size_bytes: int,
    max_bytes: int,
    model_type: type[_ModelT],
) -> _ModelT:
    if claimed_size_bytes > max_bytes:
        raise _error(M6UpgradeExecutionLedgerFailureCode.DOCUMENT_TOO_LARGE)
    encoded_size = len(raw.encode("utf-8"))
    if encoded_size > max_bytes:
        raise _error(M6UpgradeExecutionLedgerFailureCode.DOCUMENT_TOO_LARGE)
    if encoded_size != claimed_size_bytes:
        raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID)
    try:
        value = model_type.model_validate_json(raw)
        _verify_contract_document(raw, value)
        canonical, observed_sha256 = _document(value)
    except (TypeError, ValueError, ValidationError, RepositoryIntegrityError) as exc:
        raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID) from exc
    if canonical != raw or observed_sha256 != document_sha256:
        raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID)
    return value


def ledger_protocol_from_connection(
    connection: SQLiteReadSession,
    run_id: str,
) -> StoredM6UpgradeLedgerProtocol | None:
    """Load the small immutable protocol marker before any authority JSON."""

    row = connection.execute(
        """
        SELECT
            scope.execution_scope_authority_id,
            protocol.protocol_version
        FROM m6_upgrade_execution_scopes AS scope
        LEFT JOIN m6_upgrade_execution_ledger_protocols AS protocol
          ON protocol.run_id = scope.run_id
         AND protocol.execution_scope_authority_id
             = scope.execution_scope_authority_id
        WHERE scope.run_id = ?
        """,
        (run_id,),
    ).fetchone()
    if row is None:
        return None
    try:
        scope_id = _row_str(row, "execution_scope_authority_id")
        version = M6UpgradeLedgerProtocolVersion(_row_str(row, "protocol_version"))
    except (IndexError, KeyError, TypeError, ValueError, RepositoryIntegrityError) as exc:
        raise RepositoryIntegrityError("invalid M6 upgrade ledger protocol marker") from exc
    return StoredM6UpgradeLedgerProtocol(
        execution_scope_authority_id=scope_id,
        version=version,
    )


def scope_from_row(row: sqlite3.Row) -> StoredM6UpgradeScope:
    try:
        raw = _row_str(row, "scope_json")
        document_sha256 = _row_str(row, "document_sha256")
        size_bytes = _row_int(row, "size_bytes")
        scope = _parse_contract_document(
            raw=raw,
            document_sha256=document_sha256,
            claimed_size_bytes=size_bytes,
            max_bytes=MAX_M6_UPGRADE_SCOPE_BYTES,
            model_type=M6UpgradeExecutionScopeAuthority,
        )
        observed = (
            _row_str(row, "run_id"),
            _row_str(row, "execution_scope_authority_id"),
            _row_str(row, "command_id"),
            _row_str(row, "execution_dataset_snapshot_id"),
            _row_str(row, "candidate_manifest_id"),
            _row_str(row, "candidate_manifest_document_sha256"),
            _row_str(row, "candidate_config_sha256"),
            _row_str(row, "execution_component_authority_id"),
            _row_int(row, "expected_sample_count"),
            _row_int(row, "execution_start_audit_head_sequence"),
            _row_str(row, "execution_start_audit_head_hash"),
        )
        expected = (
            scope.candidate_run_id,
            scope.execution_scope_authority_id,
            scope.command.command_id,
            scope.execution_dataset.execution_dataset_snapshot_id,
            scope.candidate_manifest.manifest_id,
            scope.candidate_manifest_content_sha256,
            scope.candidate_config.config_sha256,
            scope.execution_component.component_authority_id,
            len(scope.execution_dataset.entries),
            scope.execution_start_audit_head_sequence,
            scope.execution_start_audit_head_hash,
        )
        if observed != expected:
            raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID)
        return StoredM6UpgradeScope(scope, document_sha256, size_bytes)
    except M6UpgradeExecutionLedgerError:
        raise
    except (IndexError, KeyError, TypeError, RepositoryIntegrityError) as exc:
        raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID) from exc


def _key(prefix: str, name: str) -> str:
    return f"{prefix}{name}"


def artifact_from_row(row: sqlite3.Row, *, prefix: str = "") -> StoredM6UpgradeArtifact:
    try:
        raw = _row_str(row, _key(prefix, "ref_json"))
        document_sha256 = _row_str(row, _key(prefix, "ref_document_sha256"))
        artifact = _parse_contract_document(
            raw=raw,
            document_sha256=document_sha256,
            claimed_size_bytes=_row_int(row, _key(prefix, "ref_size_bytes")),
            max_bytes=MAX_M6_UPGRADE_REF_BYTES,
            model_type=M6UpgradePhysicalArtifactRef,
        )
        observed = (
            _row_str(row, _key(prefix, "artifact_ref_id")),
            _row_str(row, _key(prefix, "source")),
            _row_str(row, _key(prefix, "kind")),
            _row_str(row, _key(prefix, "artifact_id")),
            _row_optional_str(row, _key(prefix, "container_id")),
            _row_str(row, _key(prefix, "artifact_document_sha256")),
            _row_str(row, _key(prefix, "artifact_content_sha256")),
            _row_int(row, _key(prefix, "artifact_size_bytes")),
        )
        expected = (
            artifact.artifact_ref_id,
            artifact.source.value,
            artifact.kind.value,
            artifact.artifact_id,
            artifact.container_id,
            artifact.document_sha256,
            artifact.content_sha256,
            artifact.size_bytes,
        )
        if observed != expected:
            raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID)
        return StoredM6UpgradeArtifact(
            authority=artifact,
            execution_scope_authority_id=_row_str(
                row,
                _key(prefix, "execution_scope_authority_id"),
            ),
        )
    except M6UpgradeExecutionLedgerError:
        raise
    except (IndexError, KeyError, TypeError, RepositoryIntegrityError) as exc:
        raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID) from exc


_LINK_JOIN_SQL = """
SELECT
    link.run_id,
    link.execution_entry_id,
    link.ordinal,
    link.usage,
    link.artifact_ref_id,
    link.artifact_link_id,
    link.link_json,
    link.link_document_sha256,
    link.link_size_bytes,
    ref.run_id AS ref_run_id,
    ref.execution_scope_authority_id AS ref_execution_scope_authority_id,
    ref.artifact_ref_id AS ref_artifact_ref_id,
    ref.source AS ref_source,
    ref.kind AS ref_kind,
    ref.artifact_id AS ref_artifact_id,
    ref.container_id AS ref_container_id,
    ref.artifact_document_sha256 AS ref_artifact_document_sha256,
    ref.artifact_content_sha256 AS ref_artifact_content_sha256,
    ref.artifact_size_bytes AS ref_artifact_size_bytes,
    ref.ref_json AS ref_ref_json,
    ref.ref_document_sha256 AS ref_ref_document_sha256,
    ref.ref_size_bytes AS ref_ref_size_bytes
FROM m6_upgrade_sample_artifact_links AS link
JOIN m6_upgrade_physical_artifact_refs AS ref
  ON ref.run_id = link.run_id
 AND ref.artifact_ref_id = link.artifact_ref_id
"""


def _link_from_joined_row(row: sqlite3.Row) -> M6UpgradeSampleArtifactLink:
    try:
        artifact = artifact_from_row(row, prefix="ref_")
        if _row_str(row, "run_id") != _row_str(row, "ref_run_id"):
            raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID)
        raw = _row_str(row, "link_json")
        link = _parse_contract_document(
            raw=raw,
            document_sha256=_row_str(row, "link_document_sha256"),
            claimed_size_bytes=_row_int(row, "link_size_bytes"),
            max_bytes=MAX_M6_UPGRADE_LINK_BYTES,
            model_type=M6UpgradeSampleArtifactLink,
        )
        observed = (
            _row_int(row, "ordinal"),
            _row_str(row, "usage"),
            _row_str(row, "artifact_ref_id"),
            _row_str(row, "artifact_link_id"),
        )
        expected = (
            link.ordinal,
            link.usage.value,
            link.artifact.artifact_ref_id,
            link.artifact_link_id,
        )
        if observed != expected or link.artifact != artifact.authority:
            raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID)
        return link
    except M6UpgradeExecutionLedgerError:
        raise
    except (IndexError, KeyError, TypeError, RepositoryIntegrityError) as exc:
        raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID) from exc


def _record_from_row(
    row: sqlite3.Row,
    links: tuple[M6UpgradeSampleArtifactLink, ...],
) -> M6UpgradeSampleExecutionRecord:
    try:
        if (
            _row_str(row, "record_schema_version") != "v1"
            or _row_optional_str(row, "observation_authority_id") is not None
        ):
            raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID)
        raw = _row_str(row, "record_json")
        record = _parse_contract_document(
            raw=raw,
            document_sha256=_row_str(row, "record_document_sha256"),
            claimed_size_bytes=_row_int(row, "record_size_bytes"),
            max_bytes=MAX_M6_UPGRADE_RECORD_BYTES,
            model_type=M6UpgradeSampleExecutionRecord,
        )
        observed = (
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
        )
        candidate_case = record.candidate_case
        expected = (
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
        )
        if observed != expected or record.artifact_links != links:
            raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID)
        return record
    except M6UpgradeExecutionLedgerError:
        raise
    except (IndexError, KeyError, TypeError, RepositoryIntegrityError) as exc:
        raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID) from exc


def _require_v1_record_version_columns(
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
              record_schema_version IS NOT 'v1'
              OR observation_authority_id IS NOT NULL
          )
        """,
        where_parameters,
    ).fetchone()
    try:
        if row is None or _row_int(row, "invalid_count") != 0:
            raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID)
    except M6UpgradeExecutionLedgerError:
        raise
    except (IndexError, KeyError, TypeError, RepositoryIntegrityError) as exc:
        raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID) from exc


def _load_link_groups(
    connection: SQLiteReadSession,
    run_id: str,
    *,
    expected_item_count: int,
) -> dict[str, tuple[M6UpgradeSampleArtifactLink, ...]]:
    rows = connection.execute(
        _LINK_JOIN_SQL + " WHERE link.run_id = ? ORDER BY link.execution_entry_id, link.ordinal",
        (run_id,),
    )
    grouped: dict[str, list[M6UpgradeSampleArtifactLink]] = {}
    observed_item_count = 0
    for row in rows:
        observed_item_count += 1
        execution_entry_id = _row_str(row, "execution_entry_id")
        grouped.setdefault(execution_entry_id, []).append(_link_from_joined_row(row))
    if observed_item_count != expected_item_count:
        raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID)
    return {key: tuple(values) for key, values in grouped.items()}


def record_from_connection(
    connection: SQLiteReadSession,
    run_id: str,
    execution_entry_id: str,
) -> M6UpgradeSampleExecutionRecord | None:
    _require_v1_record_version_columns(
        connection,
        where_sql="run_id = ? AND execution_entry_id = ?",
        where_parameters=(run_id, execution_entry_id),
    )
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
        raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID)
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
    link_rows = connection.execute(
        _LINK_JOIN_SQL
        + " WHERE link.run_id = ? AND link.execution_entry_id = ? ORDER BY link.ordinal",
        (run_id, execution_entry_id),
    )
    links: list[M6UpgradeSampleArtifactLink] = []
    for link_row in link_rows:
        links.append(_link_from_joined_row(link_row))
    if len(links) != link_budget.item_count:
        raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID)
    return _record_from_row(row, tuple(links))


def records_from_connection(
    connection: SQLiteReadSession,
    stored_scope: StoredM6UpgradeScope,
) -> tuple[M6UpgradeSampleExecutionRecord, ...]:
    scope = stored_scope.authority
    _require_v1_record_version_columns(
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
        if _row_str(ref_row, "execution_scope_authority_id") != scope.execution_scope_authority_id:
            raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID)
        stored_ref_ids.add(_row_str(ref_row, "artifact_ref_id"))
    if observed_ref_count != ref_budget.item_count or len(stored_ref_ids) != observed_ref_count:
        raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID)
    linked_ref_ids = {
        link.artifact.artifact_ref_id for links in link_groups.values() for link in links
    }
    if stored_ref_ids != linked_ref_ids:
        raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID)

    rows = connection.execute(
        """
        SELECT * FROM m6_upgrade_sample_executions
        WHERE run_id = ? ORDER BY ledger_sequence
        """,
        (scope.candidate_run_id,),
    )
    row_entry_ids: set[str] = set()
    records_list: list[M6UpgradeSampleExecutionRecord] = []
    for row in rows:
        execution_entry_id = _row_str(row, "execution_entry_id")
        row_entry_ids.add(execution_entry_id)
        records_list.append(_record_from_row(row, link_groups.get(execution_entry_id, ())))
    if len(records_list) != record_budget.item_count or len(row_entry_ids) != len(records_list):
        raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID)
    if set(link_groups) != row_entry_ids:
        raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID)
    records = tuple(records_list)
    previous = AUDIT_GENESIS_HASH
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
            raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID)
        previous = record.sample_execution_record_id
    return records


def seal_from_row(
    row: sqlite3.Row,
    stored_scope: StoredM6UpgradeScope,
    records: tuple[M6UpgradeSampleExecutionRecord, ...],
) -> M6UpgradeExecutionLedgerSeal:
    try:
        if _row_str(row, "seal_schema_version") != "v1":
            raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID)
        raw = _row_str(row, "seal_json")
        seal = _parse_contract_document(
            raw=raw,
            document_sha256=_row_str(row, "document_sha256"),
            claimed_size_bytes=_row_int(row, "size_bytes"),
            max_bytes=MAX_M6_UPGRADE_SEAL_BYTES,
            model_type=M6UpgradeExecutionLedgerSeal,
        )
        rebuilt = M6UpgradeExecutionLedgerSeal(
            execution_scope=stored_scope.authority,
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
        if observed != expected or seal != rebuilt:
            raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID)
        return seal
    except M6UpgradeExecutionLedgerError:
        raise
    except (IndexError, KeyError, TypeError, ValueError, ValidationError) as exc:
        raise _error(M6UpgradeExecutionLedgerFailureCode.STORED_AUTHORITY_INVALID) from exc


__all__ = [
    "MAX_M6_UPGRADE_LINK_BYTES",
    "MAX_M6_UPGRADE_RECORD_BYTES",
    "MAX_M6_UPGRADE_REF_BYTES",
    "MAX_M6_UPGRADE_SCOPE_BYTES",
    "MAX_M6_UPGRADE_SEAL_BYTES",
    "M6UpgradeLedgerProtocolVersion",
    "StoredM6UpgradeArtifact",
    "StoredM6UpgradeLedgerProtocol",
    "StoredM6UpgradeScope",
    "artifact_from_row",
    "canonical_model",
    "contract_document",
    "ledger_protocol_from_connection",
    "record_from_connection",
    "records_from_connection",
    "scope_from_row",
    "seal_from_row",
]
