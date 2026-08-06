"""Read one M6 candidate Case authority from a caller-owned SQLite cut.

The reader never opens a repository connection and never owns transaction
lifecycle.  It proves the selected revision through the complete Case-version
prefix, the complete bounded Case metadata inventory, and the run audit chain
through its current head.  Every JSON body is size-preflighted before any body
is materialized.
"""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass
from enum import StrEnum
from typing import NoReturn

from pydantic import ValidationError

from labcourt.contracts.audit import AUDIT_GENESIS_HASH, AuditEntry, validate_audit_chain
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case
from labcourt.contracts.enums import ArtifactKind, AuditAction, CaseStatus
from labcourt.contracts.events import CandidateEvent
from labcourt.contracts.m6_upgrade_execution_ledger import (
    MAX_M6_UPGRADE_LEDGER_DOCUMENT_BYTES,
    MAX_M6_UPGRADE_LEDGER_LINKS,
    M6UpgradeCandidateCaseBinding,
)
from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeSelectedCaseAuditAnchor,
)
from labcourt.contracts.references import require_reference_token
from labcourt.contracts.storage import ArtifactRef
from labcourt.exceptions import ContractViolation

from ._sqlite_m6_live_read_cut import (
    M6LiveDocumentColumn,
    M6LiveReadCutError,
    M6LiveReader,
    M6SQLiteReadSession,
    is_m6_sqlite_read_session,
)
from .sqlite_case_transitions import case_transition_audit

MAX_M6_SQLITE_CASE_DOCUMENT_BYTES = 64 * 1024 * 1024
MAX_M6_SQLITE_CASE_HISTORY_BYTES = MAX_M6_UPGRADE_LEDGER_DOCUMENT_BYTES
MAX_M6_SQLITE_CASE_HISTORY_ROWS = 4_096
MAX_M6_SQLITE_CASE_AUDIT_ROWS = MAX_M6_UPGRADE_LEDGER_LINKS
MAX_M6_SQLITE_CASE_ROWS = 1
_SQLITE_OCTET_LENGTH_MIN_VERSION = (3, 43, 0)
_USE_SQLITE_OCTET_LENGTH = sqlite3.sqlite_version_info >= _SQLITE_OCTET_LENGTH_MIN_VERSION


class M6SQLiteCaseDocumentFailureCode(StrEnum):
    """Payload-free failures at the live Case authority boundary."""

    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    TRANSACTION_REQUIRED = "TRANSACTION_REQUIRED"
    SCOPE_NOT_FOUND = "SCOPE_NOT_FOUND"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"
    DOCUMENT_NOT_FOUND = "DOCUMENT_NOT_FOUND"
    ROW_LIMIT_EXCEEDED = "ROW_LIMIT_EXCEEDED"
    DOCUMENT_TOO_LARGE = "DOCUMENT_TOO_LARGE"
    DOCUMENT_INVALID = "DOCUMENT_INVALID"
    INDEX_BINDING_MISMATCH = "INDEX_BINDING_MISMATCH"
    BINDING_MISMATCH = "BINDING_MISMATCH"
    AUDIT_MISMATCH = "AUDIT_MISMATCH"
    SELECTED_AUDIT_ANCHOR_MISMATCH = "SELECTED_AUDIT_ANCHOR_MISMATCH"
    DATABASE_REJECTED = "DATABASE_REJECTED"


class M6SQLiteCaseDocumentError(ContractViolation):
    """A candidate Case authority could not be reconstructed from storage."""

    def __init__(self, reason_code: M6SQLiteCaseDocumentFailureCode) -> None:
        if not isinstance(reason_code, M6SQLiteCaseDocumentFailureCode):
            raise TypeError("reason_code must be an M6 SQLite Case document failure code")
        self.reason_code = reason_code
        super().__init__(f"M6 SQLite Case document failed: {reason_code.value}")


@dataclass(frozen=True, slots=True)
class M6SQLiteCaseAuthorityDocument:
    """Canonical Case revision and the audit entry that committed it."""

    candidate_case_binding: M6UpgradeCandidateCaseBinding
    case: Case
    canonical_case_document: str
    audit_entry: AuditEntry
    canonical_audit_document: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.candidate_case_binding, M6UpgradeCandidateCaseBinding)
            or not isinstance(self.case, Case)
            or not isinstance(self.canonical_case_document, str)
            or not isinstance(self.audit_entry, AuditEntry)
            or not isinstance(self.canonical_audit_document, str)
        ):
            raise TypeError("M6 SQLite Case authority requires typed canonical documents")
        binding = self.candidate_case_binding
        case_sha256 = hashlib.sha256(self.canonical_case_document.encode("utf-8")).hexdigest()
        if (
            canonical_json(self.case.model_dump(mode="json")) != self.canonical_case_document
            or canonical_json(self.audit_entry.model_dump(mode="json"))
            != self.canonical_audit_document
            or self.case.case_id != binding.case_id
            or case_sha256 != binding.case_document_sha256
            or self.audit_entry.sequence != binding.case_audit_sequence
            or self.audit_entry.entry_hash != binding.case_audit_entry_hash
            or self.audit_entry.after_sha256 != case_sha256
        ):
            raise ValueError("M6 SQLite Case authority is internally inconsistent")

    @property
    def case_document_sha256(self) -> str:
        return self.candidate_case_binding.case_document_sha256

    @property
    def audit_document_sha256(self) -> str:
        return hashlib.sha256(self.canonical_audit_document.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class _CasePreflight:
    revision: int
    rowid: int
    audit_sequence: int
    document_bytes: int


@dataclass(frozen=True, slots=True)
class _CaseRootPreflight:
    rowid: int
    event_id: str
    status: CaseStatus
    created_audit_sequence: int
    current_revision: int
    latest_pack_id: str | None
    latest_pack_version: int | None
    document_bytes: int


@dataclass(frozen=True, slots=True)
class _AuditPreflight:
    sequence: int
    rowid: int
    document_bytes: int


@dataclass(frozen=True, slots=True)
class _CaseVersionIndex:
    revision: int
    status: CaseStatus
    document_sha256: str
    audit_sequence: int


@dataclass(frozen=True, slots=True)
class _EvidencePackIndex:
    version: int
    pack_id: str
    manifest_id: str
    complete: bool
    pack_input_sha256: str
    closure_input_sha256: str
    document_sha256: str
    created_audit_sequence: int


@dataclass(frozen=True, slots=True)
class _DecodedCaseRevision:
    revision: int
    case: Case
    canonical_document: str
    document_sha256: str
    audit_sequence: int


@dataclass(frozen=True, slots=True)
class _DecodedAuditEntry:
    audit: AuditEntry
    canonical_document: str


@dataclass(frozen=True, slots=True)
class _DecodedCaseRoot:
    event: CandidateEvent
    canonical_event_document: str
    status: CaseStatus
    created_audit_sequence: int
    current_revision: int
    latest_pack_id: str | None
    latest_pack_version: int | None


def _fail(reason_code: M6SQLiteCaseDocumentFailureCode) -> NoReturn:
    raise M6SQLiteCaseDocumentError(reason_code) from None


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _validated_arguments(
    connection: object,
    expected_run_id: object,
    expected_manifest_id: object,
    expected_manifest_rule_version: object,
    candidate_case_binding: object,
) -> tuple[M6SQLiteReadSession, str, str, str, M6UpgradeCandidateCaseBinding]:
    if (
        not is_m6_sqlite_read_session(connection)
        or not isinstance(expected_run_id, str)
        or not isinstance(expected_manifest_rule_version, str)
        or not expected_manifest_rule_version
        or not isinstance(candidate_case_binding, M6UpgradeCandidateCaseBinding)
    ):
        _fail(M6SQLiteCaseDocumentFailureCode.INVALID_ARGUMENT)
    try:
        run_id = require_reference_token(expected_run_id, "M6 Case source run_id")
        controlled_binding = M6UpgradeCandidateCaseBinding.model_validate(
            candidate_case_binding.model_dump(
                mode="json",
                exclude_computed_fields=True,
            )
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6SQLiteCaseDocumentFailureCode.INVALID_ARGUMENT)
    if controlled_binding != candidate_case_binding or not _is_sha256(expected_manifest_id):
        _fail(M6SQLiteCaseDocumentFailureCode.INVALID_ARGUMENT)
    if controlled_binding.case_revision > MAX_M6_SQLITE_CASE_HISTORY_ROWS:
        _fail(M6SQLiteCaseDocumentFailureCode.ROW_LIMIT_EXCEEDED)
    if controlled_binding.case_audit_sequence + 1 > MAX_M6_SQLITE_CASE_AUDIT_ROWS:
        _fail(M6SQLiteCaseDocumentFailureCode.ROW_LIMIT_EXCEEDED)
    _require_active_transaction(connection)
    assert isinstance(expected_manifest_id, str)
    return (
        connection,
        run_id,
        expected_manifest_id,
        expected_manifest_rule_version,
        controlled_binding,
    )


def _validated_selected_case_audit_anchor(
    candidate_case_binding: object,
    selected_case_audit_anchor: object,
) -> tuple[M6UpgradeCandidateCaseBinding, M6UpgradeSelectedCaseAuditAnchor]:
    if (
        not isinstance(candidate_case_binding, M6UpgradeCandidateCaseBinding)
        or type(selected_case_audit_anchor) is not M6UpgradeSelectedCaseAuditAnchor
    ):
        _fail(M6SQLiteCaseDocumentFailureCode.INVALID_ARGUMENT)
    try:
        controlled_binding = M6UpgradeCandidateCaseBinding.model_validate(
            candidate_case_binding.model_dump(
                mode="json",
                exclude_computed_fields=True,
            )
        )
        controlled_anchor = M6UpgradeSelectedCaseAuditAnchor.model_validate(
            selected_case_audit_anchor.model_dump(
                mode="json",
                exclude_computed_fields=True,
            )
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6SQLiteCaseDocumentFailureCode.INVALID_ARGUMENT)
    if (
        controlled_binding != candidate_case_binding
        or controlled_anchor != selected_case_audit_anchor
    ):
        _fail(M6SQLiteCaseDocumentFailureCode.INVALID_ARGUMENT)
    if controlled_anchor.candidate_case_binding_id != controlled_binding.case_binding_id:
        _fail(M6SQLiteCaseDocumentFailureCode.SELECTED_AUDIT_ANCHOR_MISMATCH)
    return controlled_binding, controlled_anchor


def _require_active_transaction(connection: M6SQLiteReadSession) -> None:
    try:
        in_transaction = connection.in_transaction
    except (sqlite3.Error, RuntimeError, M6LiveReadCutError):
        _fail(M6SQLiteCaseDocumentFailureCode.DATABASE_REJECTED)
    if not in_transaction:
        _fail(M6SQLiteCaseDocumentFailureCode.TRANSACTION_REQUIRED)


def _rows(
    connection: M6SQLiteReadSession,
    sql: str,
    parameters: tuple[object, ...],
    *,
    limit: int,
) -> tuple[sqlite3.Row, ...]:
    if isinstance(connection, M6LiveReader):
        try:
            sealed_cursor = connection.execute(sql, parameters)
        except (sqlite3.Error, RuntimeError, M6LiveReadCutError):
            _fail(M6SQLiteCaseDocumentFailureCode.DATABASE_REJECTED)
        try:
            try:
                rows = tuple(sealed_cursor.fetchmany(limit + 1))
            except (sqlite3.Error, RuntimeError, M6LiveReadCutError):
                _fail(M6SQLiteCaseDocumentFailureCode.DATABASE_REJECTED)
        finally:
            try:
                sealed_cursor.close()
            except (sqlite3.Error, RuntimeError, M6LiveReadCutError):
                _fail(M6SQLiteCaseDocumentFailureCode.DATABASE_REJECTED)
        return rows
    try:
        cursor = connection.cursor()
        cursor.row_factory = sqlite3.Row
        cursor.execute(sql, parameters)
    except (sqlite3.Error, RuntimeError, M6LiveReadCutError):
        _fail(M6SQLiteCaseDocumentFailureCode.DATABASE_REJECTED)
    try:
        try:
            rows = tuple(cursor.fetchmany(limit + 1))
        except (sqlite3.Error, RuntimeError, M6LiveReadCutError):
            _fail(M6SQLiteCaseDocumentFailureCode.DATABASE_REJECTED)
    finally:
        try:
            cursor.close()
        except (sqlite3.Error, RuntimeError, M6LiveReadCutError):
            _fail(M6SQLiteCaseDocumentFailureCode.DATABASE_REJECTED)
    return rows


def _text(
    row: sqlite3.Row,
    column: str,
    failure: M6SQLiteCaseDocumentFailureCode,
) -> str:
    value = row[column]
    if not isinstance(value, str):
        _fail(failure)
    return value


def _optional_text(
    row: sqlite3.Row,
    column: str,
    failure: M6SQLiteCaseDocumentFailureCode,
) -> str | None:
    value = row[column]
    if value is not None and not isinstance(value, str):
        _fail(failure)
    return value


def _integer(
    row: sqlite3.Row,
    column: str,
    failure: M6SQLiteCaseDocumentFailureCode,
) -> int:
    value = row[column]
    if not isinstance(value, int) or isinstance(value, bool):
        _fail(failure)
    return value


def _optional_integer(
    row: sqlite3.Row,
    column: str,
    failure: M6SQLiteCaseDocumentFailureCode,
) -> int | None:
    value = row[column]
    if value is not None and (not isinstance(value, int) or isinstance(value, bool)):
        _fail(failure)
    return value


def _case_status(
    row: sqlite3.Row,
    column: str,
    failure: M6SQLiteCaseDocumentFailureCode,
) -> CaseStatus:
    try:
        return CaseStatus(_text(row, column, failure))
    except ValueError:
        _fail(failure)


def _positive_rowid(row: sqlite3.Row) -> int:
    rowid = _integer(row, "document_rowid", M6SQLiteCaseDocumentFailureCode.DATABASE_REJECTED)
    if rowid <= 0:
        _fail(M6SQLiteCaseDocumentFailureCode.DATABASE_REJECTED)
    return rowid


def _require_scope(
    connection: M6SQLiteReadSession,
    run_id: str,
    manifest_id: str,
    binding: M6UpgradeCandidateCaseBinding,
) -> tuple[int, str]:
    rows = _rows(
        connection,
        """
        SELECT manifest_id, revision, audit_head_sequence, audit_head_hash
        FROM runs WHERE run_id = ?
        """,
        (run_id,),
        limit=MAX_M6_SQLITE_CASE_ROWS,
    )
    if not rows:
        _fail(M6SQLiteCaseDocumentFailureCode.SCOPE_NOT_FOUND)
    if len(rows) != 1:
        _fail(M6SQLiteCaseDocumentFailureCode.ROW_LIMIT_EXCEEDED)
    row = rows[0]
    if _text(row, "manifest_id", M6SQLiteCaseDocumentFailureCode.SCOPE_MISMATCH) != (manifest_id):
        _fail(M6SQLiteCaseDocumentFailureCode.SCOPE_MISMATCH)
    run_revision = _integer(
        row,
        "revision",
        M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH,
    )
    audit_head_sequence = _integer(
        row,
        "audit_head_sequence",
        M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH,
    )
    audit_head_hash = _text(
        row,
        "audit_head_hash",
        M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH,
    )
    if (
        run_revision != audit_head_sequence + 1
        or audit_head_sequence < -1
        or not _is_sha256(audit_head_hash)
        or (audit_head_sequence == -1) != (audit_head_hash == AUDIT_GENESIS_HASH)
    ):
        _fail(M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH)
    if binding.case_audit_sequence > audit_head_sequence:
        _fail(M6SQLiteCaseDocumentFailureCode.BINDING_MISMATCH)
    return audit_head_sequence, audit_head_hash


def _blob_size(
    connection: M6SQLiteReadSession,
    *,
    table_name: str,
    json_column: str,
    rowid: int,
) -> int:
    if isinstance(connection, M6LiveReader):
        routes = {
            ("cases", "event_json"): M6LiveDocumentColumn.CASE_ROOT_EVENT_DOCUMENT,
            ("case_versions", "case_json"): M6LiveDocumentColumn.CASE_VERSION_DOCUMENT,
            ("audit_entries", "entry_json"): M6LiveDocumentColumn.AUDIT_ENTRY_DOCUMENT,
        }
        column = routes.get((table_name, json_column))
        if column is None:
            _fail(M6SQLiteCaseDocumentFailureCode.DATABASE_REJECTED)
        try:
            return connection.document_octet_length(column, rowid)
        except M6LiveReadCutError:
            _fail(M6SQLiteCaseDocumentFailureCode.DATABASE_REJECTED)
    try:
        blob = connection.blobopen(table_name, json_column, rowid, readonly=True)
    except (sqlite3.Error, RuntimeError):
        _fail(M6SQLiteCaseDocumentFailureCode.DATABASE_REJECTED)
    try:
        try:
            return len(blob)
        except (sqlite3.Error, RuntimeError):
            _fail(M6SQLiteCaseDocumentFailureCode.DATABASE_REJECTED)
    finally:
        try:
            blob.close()
        except (sqlite3.Error, RuntimeError):
            _fail(M6SQLiteCaseDocumentFailureCode.DATABASE_REJECTED)


def _document_size(
    connection: M6SQLiteReadSession,
    row: sqlite3.Row,
    *,
    table_name: str,
    json_column: str,
) -> tuple[int, int]:
    if (
        _text(
            row,
            "document_type",
            M6SQLiteCaseDocumentFailureCode.DOCUMENT_INVALID,
        )
        != "text"
    ):
        _fail(M6SQLiteCaseDocumentFailureCode.DOCUMENT_INVALID)
    rowid = _positive_rowid(row)
    document_bytes = row["document_bytes"]
    if not _USE_SQLITE_OCTET_LENGTH:
        document_bytes = _blob_size(
            connection,
            table_name=table_name,
            json_column=json_column,
            rowid=rowid,
        )
    if (
        not isinstance(document_bytes, int)
        or isinstance(document_bytes, bool)
        or document_bytes <= 0
    ):
        _fail(M6SQLiteCaseDocumentFailureCode.DOCUMENT_INVALID)
    if document_bytes > MAX_M6_SQLITE_CASE_DOCUMENT_BYTES:
        _fail(M6SQLiteCaseDocumentFailureCode.DOCUMENT_TOO_LARGE)
    return rowid, document_bytes


def _size_projection(json_column: str) -> str:
    if _USE_SQLITE_OCTET_LENGTH:
        return f"octet_length({json_column}) AS document_bytes"
    return "NULL AS document_bytes"


def _preflight_case_root(
    connection: M6SQLiteReadSession,
    *,
    run_id: str,
    manifest_id: str,
    binding: M6UpgradeCandidateCaseBinding,
) -> _CaseRootPreflight:
    rows = _rows(
        connection,
        f"""
        SELECT rowid AS document_rowid, run_id, case_id, event_id, manifest_id,
               status, created_audit_sequence, current_revision,
               latest_pack_id, latest_pack_version,
               typeof(event_json) AS document_type,
               {_size_projection("event_json")}
        FROM cases
        WHERE run_id = ? AND case_id = ?
        """,
        (run_id, binding.case_id),
        limit=MAX_M6_SQLITE_CASE_ROWS,
    )
    if not rows:
        _fail(M6SQLiteCaseDocumentFailureCode.DOCUMENT_NOT_FOUND)
    if len(rows) != 1:
        _fail(M6SQLiteCaseDocumentFailureCode.ROW_LIMIT_EXCEEDED)
    row = rows[0]
    indexed_scope = (
        _text(row, "run_id", M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH),
        _text(row, "case_id", M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH),
        _text(row, "manifest_id", M6SQLiteCaseDocumentFailureCode.SCOPE_MISMATCH),
    )
    if indexed_scope != (run_id, binding.case_id, manifest_id):
        _fail(M6SQLiteCaseDocumentFailureCode.SCOPE_MISMATCH)
    event_id = _text(
        row,
        "event_id",
        M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH,
    )
    status = _case_status(
        row,
        "status",
        M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH,
    )
    created_audit_sequence = _integer(
        row,
        "created_audit_sequence",
        M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH,
    )
    current_revision = _integer(
        row,
        "current_revision",
        M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH,
    )
    latest_pack_id = _optional_text(
        row,
        "latest_pack_id",
        M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH,
    )
    latest_pack_version = _optional_integer(
        row,
        "latest_pack_version",
        M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH,
    )
    if created_audit_sequence < 0 or current_revision < 1:
        _fail(M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH)
    if current_revision > MAX_M6_SQLITE_CASE_HISTORY_ROWS:
        _fail(M6SQLiteCaseDocumentFailureCode.ROW_LIMIT_EXCEEDED)
    if (
        (latest_pack_id is None) != (latest_pack_version is None)
        or (latest_pack_id is not None and not _is_sha256(latest_pack_id))
        or (latest_pack_version is not None and latest_pack_version <= 0)
    ):
        _fail(M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH)
    rowid, document_bytes = _document_size(
        connection,
        row,
        table_name="cases",
        json_column="event_json",
    )
    return _CaseRootPreflight(
        rowid=rowid,
        event_id=event_id,
        status=status,
        created_audit_sequence=created_audit_sequence,
        current_revision=current_revision,
        latest_pack_id=latest_pack_id,
        latest_pack_version=latest_pack_version,
        document_bytes=document_bytes,
    )


def _preflight_case_history(
    connection: M6SQLiteReadSession,
    *,
    run_id: str,
    root_current_revision: int,
    binding: M6UpgradeCandidateCaseBinding,
) -> tuple[_CasePreflight, ...]:
    rows = _rows(
        connection,
        f"""
        SELECT rowid AS document_rowid, run_id, case_id, revision,
               audit_sequence, typeof(case_json) AS document_type,
               {_size_projection("case_json")}
        FROM case_versions
        WHERE run_id = ? AND case_id = ? AND revision <= ?
        ORDER BY revision
        """,
        (run_id, binding.case_id, binding.case_revision),
        limit=MAX_M6_SQLITE_CASE_HISTORY_ROWS,
    )
    expected_count = binding.case_revision
    observed_revisions = tuple(
        _integer(row, "revision", M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH)
        for row in rows
    )
    expected_revisions = tuple(range(1, expected_count + 1))
    if root_current_revision < binding.case_revision:
        if binding.case_revision in observed_revisions:
            _fail(M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH)
        _fail(M6SQLiteCaseDocumentFailureCode.BINDING_MISMATCH)
    if observed_revisions != expected_revisions:
        if binding.case_revision not in observed_revisions:
            _fail(M6SQLiteCaseDocumentFailureCode.DOCUMENT_NOT_FOUND)
        if len(rows) > expected_count and all(
            revision in expected_revisions for revision in observed_revisions
        ):
            _fail(M6SQLiteCaseDocumentFailureCode.ROW_LIMIT_EXCEEDED)
        _fail(M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH)
    result: list[_CasePreflight] = []
    previous_audit_sequence = -1
    for revision, row in enumerate(rows, start=1):
        if (
            _text(row, "run_id", M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH) != run_id
            or _text(
                row,
                "case_id",
                M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH,
            )
            != binding.case_id
        ):
            _fail(M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH)
        audit_sequence = _integer(
            row,
            "audit_sequence",
            M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH,
        )
        if audit_sequence <= previous_audit_sequence:
            _fail(M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH)
        rowid, document_bytes = _document_size(
            connection,
            row,
            table_name="case_versions",
            json_column="case_json",
        )
        result.append(
            _CasePreflight(
                revision=revision,
                rowid=rowid,
                audit_sequence=audit_sequence,
                document_bytes=document_bytes,
            )
        )
        previous_audit_sequence = audit_sequence
    if result[-1].audit_sequence != binding.case_audit_sequence:
        _fail(M6SQLiteCaseDocumentFailureCode.BINDING_MISMATCH)
    return tuple(result)


def _preflight_audit_chain(
    connection: M6SQLiteReadSession,
    *,
    run_id: str,
    audit_head_sequence: int,
) -> tuple[_AuditPreflight, ...]:
    if audit_head_sequence + 1 > MAX_M6_SQLITE_CASE_AUDIT_ROWS:
        _fail(M6SQLiteCaseDocumentFailureCode.ROW_LIMIT_EXCEEDED)
    expected_count = audit_head_sequence + 1
    rows = _rows(
        connection,
        f"""
        SELECT rowid AS document_rowid, run_id, sequence,
               typeof(entry_json) AS document_type,
               {_size_projection("entry_json")}
        FROM audit_entries
        WHERE run_id = ?
        ORDER BY sequence
        """,
        (run_id,),
        limit=MAX_M6_SQLITE_CASE_AUDIT_ROWS,
    )
    observed_sequences = tuple(
        _integer(row, "sequence", M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH) for row in rows
    )
    expected_sequences = tuple(range(expected_count))
    if observed_sequences != expected_sequences:
        if len(rows) < expected_count:
            _fail(M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH)
        if len(rows) > expected_count and all(
            sequence in expected_sequences for sequence in observed_sequences
        ):
            _fail(M6SQLiteCaseDocumentFailureCode.ROW_LIMIT_EXCEEDED)
        _fail(M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH)
    result: list[_AuditPreflight] = []
    for sequence, row in enumerate(rows):
        if _text(row, "run_id", M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH) != run_id:
            _fail(M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH)
        rowid, document_bytes = _document_size(
            connection,
            row,
            table_name="audit_entries",
            json_column="entry_json",
        )
        result.append(
            _AuditPreflight(
                sequence=sequence,
                rowid=rowid,
                document_bytes=document_bytes,
            )
        )
    return tuple(result)


def _require_total_preflight_budget(
    case_root: _CaseRootPreflight,
    case_history: tuple[_CasePreflight, ...],
    audit_chain: tuple[_AuditPreflight, ...],
) -> None:
    total_bytes = (
        case_root.document_bytes
        + sum(item.document_bytes for item in case_history)
        + sum(item.document_bytes for item in audit_chain)
    )
    if total_bytes > MAX_M6_SQLITE_CASE_HISTORY_BYTES:
        _fail(M6SQLiteCaseDocumentFailureCode.DOCUMENT_TOO_LARGE)


def _require_case_head_anchor(
    connection: M6SQLiteReadSession,
    *,
    run_id: str,
    case_id: str,
    root: _CaseRootPreflight,
    audit_head_sequence: int,
) -> tuple[_CaseVersionIndex, ...]:
    revision_rows = _rows(
        connection,
        """
        SELECT run_id, case_id, revision, status, document_sha256, audit_sequence
        FROM case_versions
        WHERE run_id = ? AND case_id = ?
        ORDER BY revision
        """,
        (run_id, case_id),
        limit=MAX_M6_SQLITE_CASE_HISTORY_ROWS,
    )
    observed_revisions = tuple(
        _integer(row, "revision", M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH)
        for row in revision_rows
    )
    expected_revisions = tuple(range(1, root.current_revision + 1))
    if observed_revisions != expected_revisions:
        if len(revision_rows) < root.current_revision:
            _fail(M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH)
        if len(revision_rows) > MAX_M6_SQLITE_CASE_HISTORY_ROWS or (
            len(revision_rows) > root.current_revision
            and all(revision in expected_revisions for revision in observed_revisions)
        ):
            _fail(M6SQLiteCaseDocumentFailureCode.ROW_LIMIT_EXCEEDED)
        _fail(M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH)
    result: list[_CaseVersionIndex] = []
    previous_audit_sequence = -1
    for revision, row in enumerate(revision_rows, start=1):
        if (
            _text(row, "run_id", M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH) != run_id
            or _text(row, "case_id", M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH)
            != case_id
        ):
            _fail(M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH)
        status = _case_status(
            row,
            "status",
            M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH,
        )
        document_sha256 = _text(
            row,
            "document_sha256",
            M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH,
        )
        audit_sequence = _integer(
            row,
            "audit_sequence",
            M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH,
        )
        if (
            not _is_sha256(document_sha256)
            or audit_sequence <= previous_audit_sequence
            or audit_sequence > audit_head_sequence
        ):
            _fail(M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH)
        result.append(
            _CaseVersionIndex(
                revision=revision,
                status=status,
                document_sha256=document_sha256,
                audit_sequence=audit_sequence,
            )
        )
        previous_audit_sequence = audit_sequence
    if result[0].audit_sequence != root.created_audit_sequence:
        _fail(M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH)
    if result[-1].status != root.status:
        _fail(M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH)
    return tuple(result)


def _require_evidence_pack_head_anchor(
    connection: M6SQLiteReadSession,
    *,
    run_id: str,
    case_id: str,
    manifest_id: str,
    root: _CaseRootPreflight,
    audit_head_sequence: int,
) -> tuple[_EvidencePackIndex, ...]:
    rows = _rows(
        connection,
        """
        SELECT run_id, pack_id, case_id, manifest_id, version, complete,
               pack_input_sha256, closure_input_sha256, document_sha256,
               created_audit_sequence
        FROM evidence_packs
        WHERE run_id = ? AND case_id = ?
        ORDER BY version
        """,
        (run_id, case_id),
        limit=MAX_M6_SQLITE_CASE_HISTORY_ROWS,
    )
    if len(rows) > MAX_M6_SQLITE_CASE_HISTORY_ROWS:
        _fail(M6SQLiteCaseDocumentFailureCode.ROW_LIMIT_EXCEEDED)
    if len(rows) > root.current_revision - 1:
        _fail(M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH)
    observed_versions = tuple(
        _integer(row, "version", M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH)
        for row in rows
    )
    if observed_versions != tuple(range(1, len(rows) + 1)):
        _fail(M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH)
    result: list[_EvidencePackIndex] = []
    previous_audit_sequence = -1
    seen_pack_ids: set[str] = set()
    seen_pack_inputs: set[str] = set()
    seen_complete = False
    for version, row in enumerate(rows, start=1):
        if (
            _text(row, "run_id", M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH) != run_id
            or _text(row, "case_id", M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH)
            != case_id
            or _text(
                row,
                "manifest_id",
                M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH,
            )
            != manifest_id
        ):
            _fail(M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH)
        complete_value = _integer(
            row,
            "complete",
            M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH,
        )
        pack_id = _text(
            row,
            "pack_id",
            M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH,
        )
        pack_input_sha256 = _text(
            row,
            "pack_input_sha256",
            M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH,
        )
        closure_input_sha256 = _text(
            row,
            "closure_input_sha256",
            M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH,
        )
        document_sha256 = _text(
            row,
            "document_sha256",
            M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH,
        )
        created_audit_sequence = _integer(
            row,
            "created_audit_sequence",
            M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH,
        )
        if (
            complete_value not in {0, 1}
            or not all(
                _is_sha256(value)
                for value in (
                    pack_id,
                    pack_input_sha256,
                    closure_input_sha256,
                    document_sha256,
                )
            )
            or created_audit_sequence <= previous_audit_sequence
            or created_audit_sequence > audit_head_sequence
            or pack_id in seen_pack_ids
            or pack_input_sha256 in seen_pack_inputs
            or (seen_complete and complete_value == 0)
        ):
            _fail(M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH)
        result.append(
            _EvidencePackIndex(
                version=version,
                pack_id=pack_id,
                manifest_id=manifest_id,
                complete=bool(complete_value),
                pack_input_sha256=pack_input_sha256,
                closure_input_sha256=closure_input_sha256,
                document_sha256=document_sha256,
                created_audit_sequence=created_audit_sequence,
            )
        )
        previous_audit_sequence = created_audit_sequence
        seen_pack_ids.add(pack_id)
        seen_pack_inputs.add(pack_input_sha256)
        seen_complete = seen_complete or complete_value == 1
    latest_pack = None if not result else (result[-1].pack_id, result[-1].version)
    root_latest_pack = (
        None if root.latest_pack_id is None else (root.latest_pack_id, root.latest_pack_version)
    )
    if latest_pack != root_latest_pack:
        _fail(M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH)
    return tuple(result)


def _read_case_root(
    connection: M6SQLiteReadSession,
    *,
    run_id: str,
    binding: M6UpgradeCandidateCaseBinding,
) -> sqlite3.Row:
    rows = _rows(
        connection,
        """
        SELECT rowid AS document_rowid, run_id, case_id, event_id, manifest_id,
               status, current_revision, latest_pack_id, latest_pack_version,
               event_json, event_sha256, created_audit_sequence
        FROM cases
        WHERE run_id = ? AND case_id = ?
        """,
        (run_id, binding.case_id),
        limit=MAX_M6_SQLITE_CASE_ROWS,
    )
    if len(rows) != 1:
        _fail(M6SQLiteCaseDocumentFailureCode.DATABASE_REJECTED)
    return rows[0]


def _read_case_rows(
    connection: M6SQLiteReadSession,
    *,
    run_id: str,
    binding: M6UpgradeCandidateCaseBinding,
) -> tuple[sqlite3.Row, ...]:
    rows = _rows(
        connection,
        """
        SELECT rowid AS document_rowid, run_id, case_id, revision, status,
               case_json, document_sha256, audit_sequence
        FROM case_versions
        WHERE run_id = ? AND case_id = ? AND revision <= ?
        ORDER BY revision
        """,
        (run_id, binding.case_id, binding.case_revision),
        limit=MAX_M6_SQLITE_CASE_HISTORY_ROWS,
    )
    if len(rows) != binding.case_revision:
        _fail(M6SQLiteCaseDocumentFailureCode.DATABASE_REJECTED)
    return rows


def _read_audit_rows(
    connection: M6SQLiteReadSession,
    *,
    run_id: str,
    audit_head_sequence: int,
) -> tuple[sqlite3.Row, ...]:
    rows = _rows(
        connection,
        """
        SELECT rowid AS document_rowid, run_id, sequence, manifest_id, actor, action,
               object_kind, object_id, before_sha256, after_sha256,
               recorded_at, prev_entry_hash, entry_hash,
               entry_json, document_sha256
        FROM audit_entries
        WHERE run_id = ?
        ORDER BY sequence
        """,
        (run_id,),
        limit=MAX_M6_SQLITE_CASE_AUDIT_ROWS,
    )
    if len(rows) != audit_head_sequence + 1:
        _fail(M6SQLiteCaseDocumentFailureCode.DATABASE_REJECTED)
    return rows


def _materialize_case_root(
    row: sqlite3.Row,
    preflight: _CaseRootPreflight,
    *,
    run_id: str,
    manifest_id: str,
    manifest_rule_version: str,
    case_id: str,
) -> _DecodedCaseRoot:
    event_document = _text(
        row,
        "event_json",
        M6SQLiteCaseDocumentFailureCode.DOCUMENT_INVALID,
    )
    if len(event_document.encode("utf-8")) != preflight.document_bytes:
        _fail(M6SQLiteCaseDocumentFailureCode.DATABASE_REJECTED)
    try:
        event = CandidateEvent.model_validate_json(event_document)
    except (TypeError, ValueError, ValidationError, UnicodeError):
        _fail(M6SQLiteCaseDocumentFailureCode.DOCUMENT_INVALID)
    if canonical_json(event.model_dump(mode="json")) != event_document:
        _fail(M6SQLiteCaseDocumentFailureCode.DOCUMENT_INVALID)
    indexed = (
        _integer(row, "document_rowid", M6SQLiteCaseDocumentFailureCode.DATABASE_REJECTED),
        _text(row, "run_id", M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH),
        _text(row, "case_id", M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH),
        _text(row, "event_id", M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH),
        _text(row, "manifest_id", M6SQLiteCaseDocumentFailureCode.SCOPE_MISMATCH),
        _text(row, "status", M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH),
        _integer(
            row,
            "created_audit_sequence",
            M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH,
        ),
        _integer(
            row,
            "current_revision",
            M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH,
        ),
        _optional_text(
            row,
            "latest_pack_id",
            M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH,
        ),
        _optional_integer(
            row,
            "latest_pack_version",
            M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH,
        ),
    )
    expected = (
        preflight.rowid,
        run_id,
        case_id,
        event.event_id,
        manifest_id,
        preflight.status.value,
        preflight.created_audit_sequence,
        preflight.current_revision,
        preflight.latest_pack_id,
        preflight.latest_pack_version,
    )
    if indexed != expected or event.event_id != preflight.event_id:
        _fail(M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH)
    event_sha256 = hashlib.sha256(event_document.encode("utf-8")).hexdigest()
    if (
        event.manifest_id != manifest_id
        or event.rule_version != manifest_rule_version
        or _text(
            row,
            "event_sha256",
            M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH,
        )
        != event_sha256
    ):
        _fail(M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH)
    return _DecodedCaseRoot(
        event=event,
        canonical_event_document=event_document,
        status=preflight.status,
        created_audit_sequence=preflight.created_audit_sequence,
        current_revision=preflight.current_revision,
        latest_pack_id=preflight.latest_pack_id,
        latest_pack_version=preflight.latest_pack_version,
    )


def _decode_case(
    row: sqlite3.Row,
    canonical_document: str,
    *,
    run_id: str,
    manifest_id: str,
    case_id: str,
    preflight: _CasePreflight,
) -> _DecodedCaseRevision:
    try:
        case = Case.model_validate_json(canonical_document)
    except (TypeError, ValueError, ValidationError, UnicodeError):
        _fail(M6SQLiteCaseDocumentFailureCode.DOCUMENT_INVALID)
    if canonical_json(case.model_dump(mode="json")) != canonical_document:
        _fail(M6SQLiteCaseDocumentFailureCode.DOCUMENT_INVALID)
    if case.run_id != run_id or case.manifest_id != manifest_id:
        _fail(M6SQLiteCaseDocumentFailureCode.SCOPE_MISMATCH)
    indexed = (
        _integer(row, "document_rowid", M6SQLiteCaseDocumentFailureCode.DATABASE_REJECTED),
        _text(row, "run_id", M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH),
        _text(row, "case_id", M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH),
        _integer(row, "revision", M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH),
        _text(row, "status", M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH),
        _integer(
            row,
            "audit_sequence",
            M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH,
        ),
    )
    expected = (
        preflight.rowid,
        run_id,
        case.case_id,
        preflight.revision,
        case.status.value,
        preflight.audit_sequence,
    )
    if indexed != expected or case.case_id != case_id:
        _fail(M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH)
    document_sha256 = hashlib.sha256(canonical_document.encode("utf-8")).hexdigest()
    if (
        _text(
            row,
            "document_sha256",
            M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH,
        )
        != document_sha256
    ):
        _fail(M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH)
    return _DecodedCaseRevision(
        revision=preflight.revision,
        case=case,
        canonical_document=canonical_document,
        document_sha256=document_sha256,
        audit_sequence=preflight.audit_sequence,
    )


def _decode_audit(
    row: sqlite3.Row,
    canonical_document: str,
    *,
    run_id: str,
    manifest_id: str,
    preflight: _AuditPreflight,
) -> _DecodedAuditEntry:
    try:
        audit = AuditEntry.model_validate_json(canonical_document)
    except (TypeError, ValueError, ValidationError, UnicodeError):
        _fail(M6SQLiteCaseDocumentFailureCode.DOCUMENT_INVALID)
    if canonical_json(audit.model_dump(mode="json")) != canonical_document:
        _fail(M6SQLiteCaseDocumentFailureCode.DOCUMENT_INVALID)
    if audit.run_id != run_id or audit.manifest_id != manifest_id:
        _fail(M6SQLiteCaseDocumentFailureCode.SCOPE_MISMATCH)
    indexed = (
        _integer(row, "document_rowid", M6SQLiteCaseDocumentFailureCode.DATABASE_REJECTED),
        _text(row, "run_id", M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH),
        _integer(row, "sequence", M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH),
        _text(row, "manifest_id", M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH),
        _text(row, "actor", M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH),
        _text(row, "action", M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH),
        _text(row, "object_kind", M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH),
        _text(row, "object_id", M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH),
        _optional_text(
            row,
            "before_sha256",
            M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH,
        ),
        _optional_text(
            row,
            "after_sha256",
            M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH,
        ),
        _text(row, "recorded_at", M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH),
        _text(row, "prev_entry_hash", M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH),
        _text(row, "entry_hash", M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH),
    )
    expected = (
        preflight.rowid,
        audit.run_id,
        audit.sequence,
        audit.manifest_id,
        audit.actor,
        audit.action.value,
        audit.object_ref.kind.value,
        audit.object_ref.artifact_id,
        audit.before_sha256,
        audit.after_sha256,
        audit.recorded_at,
        audit.prev_entry_hash,
        audit.entry_hash,
    )
    if indexed != expected or audit.sequence != preflight.sequence:
        _fail(M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH)
    document_sha256 = hashlib.sha256(canonical_document.encode("utf-8")).hexdigest()
    if (
        _text(row, "document_sha256", M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH)
        != document_sha256
    ):
        _fail(M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH)
    return _DecodedAuditEntry(audit=audit, canonical_document=canonical_document)


def _materialize_case_history(
    rows: tuple[sqlite3.Row, ...],
    preflights: tuple[_CasePreflight, ...],
    *,
    run_id: str,
    manifest_id: str,
    binding: M6UpgradeCandidateCaseBinding,
) -> tuple[_DecodedCaseRevision, ...]:
    decoded: list[_DecodedCaseRevision] = []
    for row, preflight in zip(rows, preflights, strict=True):
        document = _text(
            row,
            "case_json",
            M6SQLiteCaseDocumentFailureCode.DOCUMENT_INVALID,
        )
        if len(document.encode("utf-8")) != preflight.document_bytes:
            _fail(M6SQLiteCaseDocumentFailureCode.DATABASE_REJECTED)
        decoded.append(
            _decode_case(
                row,
                document,
                run_id=run_id,
                manifest_id=manifest_id,
                case_id=binding.case_id,
                preflight=preflight,
            )
        )
    return tuple(decoded)


def _materialize_audit_chain(
    rows: tuple[sqlite3.Row, ...],
    preflights: tuple[_AuditPreflight, ...],
    *,
    run_id: str,
    manifest_id: str,
) -> tuple[_DecodedAuditEntry, ...]:
    decoded: list[_DecodedAuditEntry] = []
    for row, preflight in zip(rows, preflights, strict=True):
        document = _text(
            row,
            "entry_json",
            M6SQLiteCaseDocumentFailureCode.DOCUMENT_INVALID,
        )
        if len(document.encode("utf-8")) != preflight.document_bytes:
            _fail(M6SQLiteCaseDocumentFailureCode.DATABASE_REJECTED)
        decoded.append(
            _decode_audit(
                row,
                document,
                run_id=run_id,
                manifest_id=manifest_id,
                preflight=preflight,
            )
        )
    return tuple(decoded)


def _evidence_pack_metadata_transition_allowed(
    before: CaseStatus,
    after: CaseStatus,
) -> bool:
    return after in {CaseStatus.CANDIDATE, CaseStatus.EVIDENCE_READY} or (
        before == CaseStatus.DELIBERATING and after == CaseStatus.DELIBERATING
    )


def _case_state_metadata_transition_allowed(
    before: CaseStatus,
    after: CaseStatus,
    object_kind: ArtifactKind,
) -> bool:
    if object_kind == ArtifactKind.CASE:
        return after == CaseStatus.HUMAN_REVIEW or (
            before in {CaseStatus.ESCALATED, CaseStatus.REWORK_REQUIRED}
            and after == CaseStatus.DELIBERATING
        )
    if object_kind == ArtifactKind.SCREENING_RESULT:
        return (
            before == CaseStatus.EVIDENCE_READY
            and after in {CaseStatus.SCREENED, CaseStatus.ESCALATED}
        ) or (before == CaseStatus.BACKLOGGED and after == CaseStatus.ESCALATED)
    if object_kind == ArtifactKind.PROCEDURAL_REVIEW:
        return (
            before
            in {
                CaseStatus.SCREENED,
                CaseStatus.BACKLOGGED,
                CaseStatus.DELIBERATING,
            }
            and after
            in {
                CaseStatus.READY_FOR_ALERT_POLICY,
                CaseStatus.REWORK_REQUIRED,
            }
        ) or (before == CaseStatus.REWORK_REQUIRED and after == CaseStatus.DELIBERATING)
    if object_kind == ArtifactKind.BACKLOG_ITEM:
        return (
            before
            in {
                CaseStatus.EVIDENCE_READY,
                CaseStatus.SCREENED,
                CaseStatus.DELIBERATING,
            }
            and after == CaseStatus.BACKLOGGED
        ) or (
            before == CaseStatus.BACKLOGGED
            and after
            in {
                CaseStatus.BACKLOGGED,
                CaseStatus.DELIBERATING,
                CaseStatus.HUMAN_REVIEW,
            }
        )
    if object_kind == ArtifactKind.APPEAL:
        return (before == CaseStatus.CLOSED and after == CaseStatus.APPEALED) or (
            before == CaseStatus.APPEALED
            and after in {CaseStatus.APPEALED, CaseStatus.APPEAL_RESOLVED}
        )
    return False


def _validate_case_history(
    case_root: _DecodedCaseRoot,
    case_history: tuple[_DecodedCaseRevision, ...],
    case_index: tuple[_CaseVersionIndex, ...],
    pack_index: tuple[_EvidencePackIndex, ...],
    audit_chain: tuple[_DecodedAuditEntry, ...],
    *,
    run_id: str,
    manifest_id: str,
    binding: M6UpgradeCandidateCaseBinding,
    audit_head_sequence: int,
    audit_head_hash: str,
) -> None:
    audits = tuple(item.audit for item in audit_chain)
    selected_audit = audits[binding.case_audit_sequence]
    if selected_audit.entry_hash != binding.case_audit_entry_hash:
        _fail(M6SQLiteCaseDocumentFailureCode.BINDING_MISMATCH)
    report = validate_audit_chain(
        audits,
        expected_run_id=run_id,
        expected_manifest_id=manifest_id,
        expected_head_sequence=audit_head_sequence,
        expected_head_hash=audit_head_hash,
    )
    if not report.passed:
        _fail(M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH)
    selected_index = case_index[: binding.case_revision]
    if len(selected_index) != len(case_history) or any(
        revision.revision != indexed.revision
        or revision.case.status != indexed.status
        or revision.document_sha256 != indexed.document_sha256
        or revision.audit_sequence != indexed.audit_sequence
        for revision, indexed in zip(case_history, selected_index, strict=True)
    ):
        _fail(M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH)
    initial = case_history[0]
    expected_initial_case = Case(
        run_id=run_id,
        status=CaseStatus.CANDIDATE,
        event=case_root.event,
        manifest_id=manifest_id,
    )
    if (
        initial.case != expected_initial_case
        or initial.audit_sequence != case_root.created_audit_sequence
    ):
        _fail(M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH)
    if case_root.current_revision == binding.case_revision:
        current = case_history[-1].case
        expected_latest_pack = (
            None
            if not current.evidence_packs
            else (
                current.evidence_packs[-1].pack_id,
                current.evidence_packs[-1].version,
            )
        )
        actual_latest_pack = (
            None
            if case_root.latest_pack_id is None
            else (case_root.latest_pack_id, case_root.latest_pack_version)
        )
        if current.status != case_root.status or actual_latest_pack != (expected_latest_pack):
            _fail(M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH)
    audits_by_sequence = {audit.sequence: audit for audit in audits}
    packs_by_audit_sequence = {pack.created_audit_sequence: pack for pack in pack_index}
    case_publication_sequences: list[int] = []
    previous_index_sha256: str | None = None
    previous_index_status: CaseStatus | None = None
    for indexed in case_index:
        audit = audits_by_sequence.get(indexed.audit_sequence)
        case_ref = ArtifactRef(kind=ArtifactKind.CASE, artifact_id=binding.case_id)
        metadata_action_matches = False
        if audit is not None:
            if indexed.revision == 1:
                metadata_action_matches = (
                    audit.action == AuditAction.CASE_CREATED and audit.object_ref == case_ref
                )
            elif audit.action == AuditAction.EVIDENCE_PACK_PUBLISHED:
                assert previous_index_status is not None
                metadata_action_matches = (
                    audit.object_ref == case_ref
                    and _evidence_pack_metadata_transition_allowed(
                        previous_index_status,
                        indexed.status,
                    )
                )
                pack = packs_by_audit_sequence.get(indexed.audit_sequence)
                if pack is None or (
                    (not pack.complete and indexed.status != CaseStatus.CANDIDATE)
                    or (
                        pack.complete
                        and indexed.status
                        not in {
                            CaseStatus.EVIDENCE_READY,
                            CaseStatus.DELIBERATING,
                        }
                    )
                ):
                    metadata_action_matches = False
                else:
                    case_publication_sequences.append(indexed.audit_sequence)
            elif audit.action == AuditAction.CASE_CLOSED:
                metadata_action_matches = (
                    previous_index_status == CaseStatus.READY_FOR_ALERT_POLICY
                    and indexed.status == CaseStatus.CLOSED
                    and audit.object_ref.kind
                    in {
                        ArtifactKind.CASE,
                        ArtifactKind.ALERT,
                    }
                    and (audit.object_ref.kind != ArtifactKind.CASE or audit.object_ref == case_ref)
                )
            elif audit.action == AuditAction.CASE_STATE_CHANGED:
                assert previous_index_status is not None
                metadata_action_matches = _case_state_metadata_transition_allowed(
                    previous_index_status,
                    indexed.status,
                    audit.object_ref.kind,
                ) and (audit.object_ref.kind != ArtifactKind.CASE or audit.object_ref == case_ref)
        if (
            audit is None
            or not metadata_action_matches
            or audit.before_sha256 != previous_index_sha256
            or audit.after_sha256 != indexed.document_sha256
        ):
            _fail(M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH)
        previous_index_sha256 = indexed.document_sha256
        previous_index_status = indexed.status
    pack_publication_sequences = tuple(pack.created_audit_sequence for pack in pack_index)
    audit_publication_sequences = tuple(
        audit.sequence
        for audit in audits
        if audit.action == AuditAction.EVIDENCE_PACK_PUBLISHED
        and audit.object_ref
        == ArtifactRef(
            kind=ArtifactKind.CASE,
            artifact_id=binding.case_id,
        )
    )
    if (
        tuple(case_publication_sequences) != pack_publication_sequences
        or tuple(case_publication_sequences) != audit_publication_sequences
    ):
        _fail(M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH)
    previous_case: Case | None = None
    previous_sha256: str | None = None
    for revision in case_history:
        audit = audits_by_sequence.get(revision.audit_sequence)
        if audit is None:
            _fail(M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH)
        if revision.revision == 1:
            expected_action = AuditAction.CASE_CREATED
            expected_object_ref = ArtifactRef(
                kind=ArtifactKind.CASE,
                artifact_id=binding.case_id,
            )
        else:
            assert previous_case is not None
            transition = case_transition_audit(previous_case, revision.case)
            if transition is None:
                _fail(M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH)
            expected_action, expected_object_ref = transition
        if (
            audit.action != expected_action
            or audit.object_ref != expected_object_ref
            or audit.before_sha256 != previous_sha256
            or audit.after_sha256 != revision.document_sha256
        ):
            _fail(M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH)
        previous_case = revision.case
        previous_sha256 = revision.document_sha256
    selected_case = case_history[-1]
    selected_pack_index = tuple(
        pack for pack in pack_index if pack.created_audit_sequence <= selected_case.audit_sequence
    )
    if len(selected_pack_index) != len(selected_case.case.evidence_packs):
        _fail(M6SQLiteCaseDocumentFailureCode.AUDIT_MISMATCH)
    for indexed_pack, embedded_pack in zip(
        selected_pack_index,
        selected_case.case.evidence_packs,
        strict=True,
    ):
        canonical_pack = canonical_json(embedded_pack.model_dump(mode="json"))
        embedded_metadata = (
            embedded_pack.version,
            embedded_pack.pack_id,
            embedded_pack.manifest_id,
            embedded_pack.complete,
            embedded_pack.pack_input_sha256,
            embedded_pack.closure_input_sha256,
            hashlib.sha256(canonical_pack.encode("utf-8")).hexdigest(),
        )
        indexed_metadata = (
            indexed_pack.version,
            indexed_pack.pack_id,
            indexed_pack.manifest_id,
            indexed_pack.complete,
            indexed_pack.pack_input_sha256,
            indexed_pack.closure_input_sha256,
            indexed_pack.document_sha256,
        )
        if indexed_metadata != embedded_metadata:
            _fail(M6SQLiteCaseDocumentFailureCode.INDEX_BINDING_MISMATCH)


def read_m6_sqlite_case_authority(
    *,
    connection: M6SQLiteReadSession,
    expected_run_id: str,
    expected_manifest_id: str,
    expected_manifest_rule_version: str,
    candidate_case_binding: M6UpgradeCandidateCaseBinding,
) -> M6SQLiteCaseAuthorityDocument:
    """Reconstruct a bound Case revision and prove its histories on one live cut."""

    controlled, run_id, manifest_id, manifest_rule_version, binding = _validated_arguments(
        connection,
        expected_run_id,
        expected_manifest_id,
        expected_manifest_rule_version,
        candidate_case_binding,
    )
    try:
        run_audit_head = _require_scope(controlled, run_id, manifest_id, binding)
        case_root_preflight = _preflight_case_root(
            controlled,
            run_id=run_id,
            manifest_id=manifest_id,
            binding=binding,
        )
        case_preflights = _preflight_case_history(
            controlled,
            run_id=run_id,
            root_current_revision=case_root_preflight.current_revision,
            binding=binding,
        )
        audit_preflights = _preflight_audit_chain(
            controlled,
            run_id=run_id,
            audit_head_sequence=run_audit_head[0],
        )
        case_index = _require_case_head_anchor(
            controlled,
            run_id=run_id,
            case_id=binding.case_id,
            root=case_root_preflight,
            audit_head_sequence=run_audit_head[0],
        )
        pack_index = _require_evidence_pack_head_anchor(
            controlled,
            run_id=run_id,
            case_id=binding.case_id,
            manifest_id=manifest_id,
            root=case_root_preflight,
            audit_head_sequence=run_audit_head[0],
        )
        _require_total_preflight_budget(
            case_root_preflight,
            case_preflights,
            audit_preflights,
        )
        _require_active_transaction(controlled)

        case_root_row = _read_case_root(controlled, run_id=run_id, binding=binding)
        case_rows = _read_case_rows(controlled, run_id=run_id, binding=binding)
        audit_rows = _read_audit_rows(
            controlled,
            run_id=run_id,
            audit_head_sequence=run_audit_head[0],
        )
        case_root = _materialize_case_root(
            case_root_row,
            case_root_preflight,
            run_id=run_id,
            manifest_id=manifest_id,
            manifest_rule_version=manifest_rule_version,
            case_id=binding.case_id,
        )
        case_history = _materialize_case_history(
            case_rows,
            case_preflights,
            run_id=run_id,
            manifest_id=manifest_id,
            binding=binding,
        )
        audit_chain = _materialize_audit_chain(
            audit_rows,
            audit_preflights,
            run_id=run_id,
            manifest_id=manifest_id,
        )
        _validate_case_history(
            case_root,
            case_history,
            case_index,
            pack_index,
            audit_chain,
            run_id=run_id,
            manifest_id=manifest_id,
            binding=binding,
            audit_head_sequence=run_audit_head[0],
            audit_head_hash=run_audit_head[1],
        )
        selected_case = case_history[-1]
        selected_audit = audit_chain[binding.case_audit_sequence]
        if (
            selected_case.document_sha256 != binding.case_document_sha256
            or selected_case.audit_sequence != binding.case_audit_sequence
            or selected_audit.audit.entry_hash != binding.case_audit_entry_hash
        ):
            _fail(M6SQLiteCaseDocumentFailureCode.BINDING_MISMATCH)
        result = M6SQLiteCaseAuthorityDocument(
            candidate_case_binding=binding,
            case=selected_case.case,
            canonical_case_document=selected_case.canonical_document,
            audit_entry=selected_audit.audit,
            canonical_audit_document=selected_audit.canonical_document,
        )
        _require_active_transaction(controlled)
        return result
    except M6SQLiteCaseDocumentError as error:
        raise error from None
    except (sqlite3.Error, M6LiveReadCutError, KeyError, IndexError):
        _fail(M6SQLiteCaseDocumentFailureCode.DATABASE_REJECTED)
    except UnicodeError:
        _fail(M6SQLiteCaseDocumentFailureCode.DOCUMENT_INVALID)


def read_m6_sqlite_case_authority_v3(
    *,
    connection: M6SQLiteReadSession,
    expected_run_id: str,
    expected_manifest_id: str,
    expected_manifest_rule_version: str,
    candidate_case_binding: M6UpgradeCandidateCaseBinding,
    selected_case_audit_anchor: M6UpgradeSelectedCaseAuditAnchor,
) -> M6SQLiteCaseAuthorityDocument:
    """Read one Case authority and exact-join its selected audit action/object anchor."""

    controlled_binding, controlled_anchor = _validated_selected_case_audit_anchor(
        candidate_case_binding,
        selected_case_audit_anchor,
    )
    authority = read_m6_sqlite_case_authority(
        connection=connection,
        expected_run_id=expected_run_id,
        expected_manifest_id=expected_manifest_id,
        expected_manifest_rule_version=expected_manifest_rule_version,
        candidate_case_binding=controlled_binding,
    )
    try:
        actual_anchor = M6UpgradeSelectedCaseAuditAnchor(
            candidate_case_binding_id=authority.candidate_case_binding.case_binding_id,
            action=authority.audit_entry.action,
            object_ref=authority.audit_entry.object_ref,
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6SQLiteCaseDocumentFailureCode.SELECTED_AUDIT_ANCHOR_MISMATCH)
    if actual_anchor != controlled_anchor:
        _fail(M6SQLiteCaseDocumentFailureCode.SELECTED_AUDIT_ANCHOR_MISMATCH)
    return authority


__all__ = [
    "MAX_M6_SQLITE_CASE_AUDIT_ROWS",
    "MAX_M6_SQLITE_CASE_DOCUMENT_BYTES",
    "MAX_M6_SQLITE_CASE_HISTORY_BYTES",
    "MAX_M6_SQLITE_CASE_HISTORY_ROWS",
    "MAX_M6_SQLITE_CASE_ROWS",
    "M6SQLiteCaseAuthorityDocument",
    "M6SQLiteCaseDocumentError",
    "M6SQLiteCaseDocumentFailureCode",
    "read_m6_sqlite_case_authority",
    "read_m6_sqlite_case_authority_v3",
]
