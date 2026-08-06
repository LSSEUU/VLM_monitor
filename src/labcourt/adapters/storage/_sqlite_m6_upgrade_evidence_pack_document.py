"""Selected-Case-bound SQLite planning for one M2 EvidencePack document.

Planning reads only the target row's metadata and byte length.  The canonical
authority comes from the already-validated selected Case, so an observed pack
identifier cannot turn the independent ``evidence_packs`` table into a new
membership authority.  The independent ``pack_json`` body is read only by the
late resolver, after the caller has admitted the plan to its whole-sample
budget, and must match the selected Case bytes exactly.
"""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass
from enum import StrEnum
from typing import NoReturn

from pydantic import ValidationError

from labcourt.contracts.audit import AuditEntry
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case
from labcourt.contracts.evidence import EvidencePack
from labcourt.contracts.m6_upgrade_execution_ledger import M6UpgradeCandidateCaseBinding
from labcourt.contracts.m6_upgrade_physical import (
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactRef,
    M6UpgradePhysicalArtifactSource,
)
from labcourt.contracts.references import require_reference_token
from labcourt.exceptions import ContractViolation

from ._sqlite_m6_live_read_cut import (
    M6LiveDocumentColumn,
    M6LiveReadCutError,
    M6LiveReader,
    M6SQLiteReadSession,
    is_m6_sqlite_read_session,
)
from ._sqlite_m6_upgrade_case_document import M6SQLiteCaseAuthorityDocument
from ._sqlite_m6_upgrade_physical_documents import M6SQLiteCanonicalPhysicalDocument

MAX_M6_SQLITE_EVIDENCE_PACK_DOCUMENT_BYTES = 64 * 1024 * 1024
MAX_M6_SQLITE_EVIDENCE_PACK_ROWS = 1
_SQLITE_OCTET_LENGTH_MIN_VERSION = (3, 43, 0)
_USE_SQLITE_OCTET_LENGTH = sqlite3.sqlite_version_info >= _SQLITE_OCTET_LENGTH_MIN_VERSION


class M6SQLiteEvidencePackDocumentFailureCode(StrEnum):
    """Payload-free selected-Case EvidencePack failure reasons."""

    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    TRANSACTION_REQUIRED = "TRANSACTION_REQUIRED"
    SCOPE_NOT_FOUND = "SCOPE_NOT_FOUND"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"
    DOCUMENT_NOT_FOUND = "DOCUMENT_NOT_FOUND"
    ROW_LIMIT_EXCEEDED = "ROW_LIMIT_EXCEEDED"
    DOCUMENT_TOO_LARGE = "DOCUMENT_TOO_LARGE"
    DOCUMENT_INVALID = "DOCUMENT_INVALID"
    INDEX_BINDING_MISMATCH = "INDEX_BINDING_MISMATCH"
    SELECTED_CASE_MEMBERSHIP_MISMATCH = "SELECTED_CASE_MEMBERSHIP_MISMATCH"
    PHYSICAL_PLAN_INVALID = "PHYSICAL_PLAN_INVALID"
    DATABASE_REJECTED = "DATABASE_REJECTED"


class M6SQLiteEvidencePackDocumentError(ContractViolation):
    """A selected-Case EvidencePack could not be planned or resolved."""

    def __init__(self, reason_code: M6SQLiteEvidencePackDocumentFailureCode) -> None:
        if not isinstance(reason_code, M6SQLiteEvidencePackDocumentFailureCode):
            raise TypeError("reason_code must be an M6 SQLite EvidencePack failure code")
        self.reason_code = reason_code
        super().__init__(f"M6 SQLite EvidencePack document failed: {reason_code.value}")


def _sha256(document: str) -> str:
    return hashlib.sha256(document.encode("utf-8")).hexdigest()


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _plan_is_consistent(plan: object) -> bool:
    if type(plan) is not M6SQLiteEvidencePackPhysicalPlan:
        return False
    if (
        type(plan.selected_case_binding) is not M6UpgradeCandidateCaseBinding
        or type(plan.pack_authority) is not EvidencePack
        or not isinstance(plan.expected_canonical_document, str)
        or type(plan.document_rowid) is not int
        or plan.document_rowid <= 0
        or type(plan.created_audit_sequence) is not int
        or plan.created_audit_sequence < 0
        or type(plan.planned_artifact_ref) is not M6UpgradePhysicalArtifactRef
    ):
        return False
    binding = plan.selected_case_binding
    pack = plan.pack_authority
    try:
        controlled_binding = M6UpgradeCandidateCaseBinding.model_validate(
            binding.model_dump(mode="json", exclude_computed_fields=True)
        )
        controlled_pack = EvidencePack.model_validate(
            pack.model_dump(mode="json", exclude_computed_fields=True)
        )
        canonical_document = canonical_json(pack.model_dump(mode="json"))
        canonical_bytes = canonical_document.encode("utf-8")
        document_sha256 = hashlib.sha256(canonical_bytes).hexdigest()
    except (AttributeError, TypeError, ValueError, ValidationError, UnicodeError):
        return False
    artifact_ref = plan.planned_artifact_ref
    return (
        controlled_binding == binding
        and controlled_pack == pack
        and plan.expected_canonical_document == canonical_document
        and pack.case_id == binding.case_id
        and plan.created_audit_sequence <= binding.case_audit_sequence
        and artifact_ref.source == M6UpgradePhysicalArtifactSource.M2_EVIDENCE
        and artifact_ref.kind == M6UpgradePhysicalArtifactKind.EVIDENCE_PACK
        and artifact_ref.artifact_id == pack.pack_id
        and artifact_ref.container_id is None
        and artifact_ref.document_sha256 == document_sha256
        and artifact_ref.content_sha256 == document_sha256
        and artifact_ref.size_bytes == len(canonical_bytes)
    )


@dataclass(frozen=True, slots=True)
class M6SQLiteEvidencePackPhysicalPlan:
    """Selected binding, expected bytes, and metadata-only physical plan."""

    selected_case_binding: M6UpgradeCandidateCaseBinding
    pack_authority: EvidencePack
    expected_canonical_document: str
    document_rowid: int
    created_audit_sequence: int
    planned_artifact_ref: M6UpgradePhysicalArtifactRef

    def __post_init__(self) -> None:
        if (
            type(self.selected_case_binding) is not M6UpgradeCandidateCaseBinding
            or type(self.pack_authority) is not EvidencePack
            or not isinstance(self.expected_canonical_document, str)
            or type(self.document_rowid) is not int
            or type(self.created_audit_sequence) is not int
            or type(self.planned_artifact_ref) is not M6UpgradePhysicalArtifactRef
        ):
            raise TypeError("M6 SQLite EvidencePack physical plan requires typed content")
        if not _plan_is_consistent(self):
            raise ValueError("M6 SQLite EvidencePack physical plan is inconsistent")


@dataclass(frozen=True, slots=True)
class _StoredEvidencePackMetadata:
    document_rowid: int
    run_id: str
    pack_id: str
    case_id: str
    manifest_id: str
    version: int
    complete: int
    pack_input_sha256: str
    closure_input_sha256: str
    document_sha256: str
    created_audit_sequence: int
    document_bytes: int


def _fail(reason_code: M6SQLiteEvidencePackDocumentFailureCode) -> NoReturn:
    raise M6SQLiteEvidencePackDocumentError(reason_code) from None


def _require_active_transaction(connection: M6SQLiteReadSession) -> None:
    try:
        in_transaction = connection.in_transaction
    except (sqlite3.Error, RuntimeError, M6LiveReadCutError):
        _fail(M6SQLiteEvidencePackDocumentFailureCode.DATABASE_REJECTED)
    if type(in_transaction) is not bool:
        _fail(M6SQLiteEvidencePackDocumentFailureCode.DATABASE_REJECTED)
    if not in_transaction:
        _fail(M6SQLiteEvidencePackDocumentFailureCode.TRANSACTION_REQUIRED)


def _case_authority_is_consistent(authority: M6SQLiteCaseAuthorityDocument) -> bool:
    binding = authority.candidate_case_binding
    case = authority.case
    audit = authority.audit_entry
    if (
        type(binding) is not M6UpgradeCandidateCaseBinding
        or type(case) is not Case
        or type(audit) is not AuditEntry
        or not isinstance(authority.canonical_case_document, str)
        or not isinstance(authority.canonical_audit_document, str)
    ):
        return False
    try:
        controlled_binding = M6UpgradeCandidateCaseBinding.model_validate(
            binding.model_dump(mode="json", exclude_computed_fields=True)
        )
        controlled_case = Case.model_validate(
            case.model_dump(mode="json", exclude_computed_fields=True)
        )
        controlled_audit = AuditEntry.model_validate(
            audit.model_dump(mode="json", exclude_computed_fields=True)
        )
        case_sha256 = _sha256(authority.canonical_case_document)
        return (
            controlled_binding == binding
            and controlled_case == case
            and controlled_audit == audit
            and canonical_json(case.model_dump(mode="json")) == authority.canonical_case_document
            and canonical_json(audit.model_dump(mode="json")) == authority.canonical_audit_document
            and case.case_id == binding.case_id
            and case_sha256 == binding.case_document_sha256
            and audit.sequence == binding.case_audit_sequence
            and audit.entry_hash == binding.case_audit_entry_hash
            and audit.after_sha256 == case_sha256
        )
    except (AttributeError, TypeError, ValueError, ValidationError, UnicodeError):
        return False


def _validated_plan_arguments(
    connection: object,
    expected_run_id: object,
    expected_manifest_id: object,
    selected_case_authority: object,
    pack_id: object,
) -> tuple[
    M6SQLiteReadSession,
    str,
    str,
    M6SQLiteCaseAuthorityDocument,
    EvidencePack,
]:
    if (
        not is_m6_sqlite_read_session(connection)
        or not isinstance(expected_run_id, str)
        or not isinstance(expected_manifest_id, str)
        or type(selected_case_authority) is not M6SQLiteCaseAuthorityDocument
        or not isinstance(pack_id, str)
    ):
        _fail(M6SQLiteEvidencePackDocumentFailureCode.INVALID_ARGUMENT)
    try:
        run_id = require_reference_token(
            expected_run_id,
            "M6 selected-Case EvidencePack run_id",
        )
        controlled_pack_id = require_reference_token(
            pack_id,
            "M6 selected-Case EvidencePack pack_id",
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6SQLiteEvidencePackDocumentFailureCode.INVALID_ARGUMENT)
    if not _is_sha256(expected_manifest_id):
        _fail(M6SQLiteEvidencePackDocumentFailureCode.INVALID_ARGUMENT)
    _require_active_transaction(connection)
    if not _case_authority_is_consistent(selected_case_authority):
        _fail(M6SQLiteEvidencePackDocumentFailureCode.INVALID_ARGUMENT)
    if (
        selected_case_authority.case.run_id != run_id
        or selected_case_authority.case.manifest_id != expected_manifest_id
    ):
        _fail(M6SQLiteEvidencePackDocumentFailureCode.SCOPE_MISMATCH)
    matching_packs = tuple(
        pack
        for pack in selected_case_authority.case.evidence_packs
        if pack.pack_id == controlled_pack_id
    )
    if len(matching_packs) != 1:
        _fail(M6SQLiteEvidencePackDocumentFailureCode.SELECTED_CASE_MEMBERSHIP_MISMATCH)
    return (
        connection,
        run_id,
        expected_manifest_id,
        selected_case_authority,
        matching_packs[0],
    )


def _validated_resolve_arguments(
    connection: object,
    physical_plan: object,
) -> tuple[M6SQLiteReadSession, M6SQLiteEvidencePackPhysicalPlan]:
    if not is_m6_sqlite_read_session(connection):
        _fail(M6SQLiteEvidencePackDocumentFailureCode.INVALID_ARGUMENT)
    if type(physical_plan) is not M6SQLiteEvidencePackPhysicalPlan:
        _fail(M6SQLiteEvidencePackDocumentFailureCode.INVALID_ARGUMENT)
    _require_active_transaction(connection)
    if not _plan_is_consistent(physical_plan):
        _fail(M6SQLiteEvidencePackDocumentFailureCode.PHYSICAL_PLAN_INVALID)
    if physical_plan.planned_artifact_ref.size_bytes > MAX_M6_SQLITE_EVIDENCE_PACK_DOCUMENT_BYTES:
        _fail(M6SQLiteEvidencePackDocumentFailureCode.DOCUMENT_TOO_LARGE)
    return connection, physical_plan


def _rows(
    connection: M6SQLiteReadSession,
    sql: str,
    parameters: tuple[object, ...],
    *,
    limit: int,
) -> tuple[sqlite3.Row, ...]:
    if isinstance(connection, M6LiveReader):
        try:
            cursor = connection.execute(sql, parameters)
        except (sqlite3.Error, RuntimeError, M6LiveReadCutError):
            _fail(M6SQLiteEvidencePackDocumentFailureCode.DATABASE_REJECTED)
        try:
            try:
                rows = tuple(cursor.fetchmany(limit + 1))
            except (sqlite3.Error, RuntimeError, M6LiveReadCutError):
                _fail(M6SQLiteEvidencePackDocumentFailureCode.DATABASE_REJECTED)
        finally:
            try:
                cursor.close()
            except (sqlite3.Error, RuntimeError, M6LiveReadCutError):
                _fail(M6SQLiteEvidencePackDocumentFailureCode.DATABASE_REJECTED)
        return rows
    try:
        raw_cursor = connection.cursor()
        raw_cursor.row_factory = sqlite3.Row
        raw_cursor.execute(sql, parameters)
    except (sqlite3.Error, RuntimeError, M6LiveReadCutError):
        _fail(M6SQLiteEvidencePackDocumentFailureCode.DATABASE_REJECTED)
    try:
        try:
            rows = tuple(raw_cursor.fetchmany(limit + 1))
        except (sqlite3.Error, RuntimeError, M6LiveReadCutError):
            _fail(M6SQLiteEvidencePackDocumentFailureCode.DATABASE_REJECTED)
    finally:
        try:
            raw_cursor.close()
        except (sqlite3.Error, RuntimeError, M6LiveReadCutError):
            _fail(M6SQLiteEvidencePackDocumentFailureCode.DATABASE_REJECTED)
    return rows


def _require_scope(
    connection: M6SQLiteReadSession,
    run_id: str,
    manifest_id: str,
) -> None:
    rows = _rows(
        connection,
        "SELECT manifest_id FROM runs WHERE run_id = ?",
        (run_id,),
        limit=MAX_M6_SQLITE_EVIDENCE_PACK_ROWS,
    )
    if not rows:
        _fail(M6SQLiteEvidencePackDocumentFailureCode.SCOPE_NOT_FOUND)
    if len(rows) != 1:
        _fail(M6SQLiteEvidencePackDocumentFailureCode.ROW_LIMIT_EXCEEDED)
    observed_manifest_id = rows[0]["manifest_id"]
    if not isinstance(observed_manifest_id, str) or observed_manifest_id != manifest_id:
        _fail(M6SQLiteEvidencePackDocumentFailureCode.SCOPE_MISMATCH)


def _document_text(row: sqlite3.Row, column: str) -> str:
    value = row[column]
    if not isinstance(value, str):
        _fail(M6SQLiteEvidencePackDocumentFailureCode.DOCUMENT_INVALID)
    return value


def _index_text(row: sqlite3.Row, column: str) -> str:
    value = row[column]
    if not isinstance(value, str):
        _fail(M6SQLiteEvidencePackDocumentFailureCode.INDEX_BINDING_MISMATCH)
    return value


def _index_integer(row: sqlite3.Row, column: str) -> int:
    value = row[column]
    if not isinstance(value, int) or isinstance(value, bool):
        _fail(M6SQLiteEvidencePackDocumentFailureCode.INDEX_BINDING_MISMATCH)
    return value


def _preflight_row(
    connection: M6SQLiteReadSession,
    run_id: str,
    pack_id: str,
) -> tuple[sqlite3.Row, int]:
    size_projection = (
        "octet_length(pack_json) AS document_bytes"
        if _USE_SQLITE_OCTET_LENGTH
        else "NULL AS document_bytes"
    )
    rows = _rows(
        connection,
        f"""
        SELECT rowid AS document_rowid,
               run_id, pack_id, case_id, manifest_id, version, complete,
               pack_input_sha256, closure_input_sha256,
               document_sha256, created_audit_sequence,
               typeof(pack_json) AS document_type,
               {size_projection}
        FROM evidence_packs
        WHERE run_id = ? AND pack_id = ?
        """,
        (run_id, pack_id),
        limit=MAX_M6_SQLITE_EVIDENCE_PACK_ROWS,
    )
    if not rows:
        _fail(M6SQLiteEvidencePackDocumentFailureCode.DOCUMENT_NOT_FOUND)
    if len(rows) != 1:
        _fail(M6SQLiteEvidencePackDocumentFailureCode.ROW_LIMIT_EXCEEDED)
    row = rows[0]
    if _document_text(row, "document_type") != "text":
        _fail(M6SQLiteEvidencePackDocumentFailureCode.DOCUMENT_INVALID)
    document_rowid = row["document_rowid"]
    if (
        not isinstance(document_rowid, int)
        or isinstance(document_rowid, bool)
        or document_rowid <= 0
    ):
        _fail(M6SQLiteEvidencePackDocumentFailureCode.DATABASE_REJECTED)
    document_bytes = row["document_bytes"]
    if not _USE_SQLITE_OCTET_LENGTH:
        if isinstance(connection, M6LiveReader):
            try:
                document_bytes = connection.document_octet_length(
                    M6LiveDocumentColumn.EVIDENCE_PACK_DOCUMENT,
                    document_rowid,
                )
            except (sqlite3.Error, RuntimeError, M6LiveReadCutError):
                _fail(M6SQLiteEvidencePackDocumentFailureCode.DATABASE_REJECTED)
        else:
            try:
                blob = connection.blobopen(
                    "evidence_packs",
                    "pack_json",
                    document_rowid,
                    readonly=True,
                )
            except (sqlite3.Error, RuntimeError):
                _fail(M6SQLiteEvidencePackDocumentFailureCode.DATABASE_REJECTED)
            try:
                try:
                    document_bytes = len(blob)
                except (sqlite3.Error, RuntimeError):
                    _fail(M6SQLiteEvidencePackDocumentFailureCode.DATABASE_REJECTED)
            finally:
                try:
                    blob.close()
                except (sqlite3.Error, RuntimeError):
                    _fail(M6SQLiteEvidencePackDocumentFailureCode.DATABASE_REJECTED)
    if (
        not isinstance(document_bytes, int)
        or isinstance(document_bytes, bool)
        or document_bytes <= 0
    ):
        _fail(M6SQLiteEvidencePackDocumentFailureCode.DOCUMENT_INVALID)
    if document_bytes > MAX_M6_SQLITE_EVIDENCE_PACK_DOCUMENT_BYTES:
        _fail(M6SQLiteEvidencePackDocumentFailureCode.DOCUMENT_TOO_LARGE)
    return row, document_bytes


def _stored_metadata(
    row: sqlite3.Row,
    document_bytes: int,
) -> _StoredEvidencePackMetadata:
    document_rowid = _index_integer(row, "document_rowid")
    version = _index_integer(row, "version")
    complete = _index_integer(row, "complete")
    created_audit_sequence = _index_integer(row, "created_audit_sequence")
    metadata = _StoredEvidencePackMetadata(
        document_rowid=document_rowid,
        run_id=_index_text(row, "run_id"),
        pack_id=_index_text(row, "pack_id"),
        case_id=_index_text(row, "case_id"),
        manifest_id=_index_text(row, "manifest_id"),
        version=version,
        complete=complete,
        pack_input_sha256=_index_text(row, "pack_input_sha256"),
        closure_input_sha256=_index_text(row, "closure_input_sha256"),
        document_sha256=_index_text(row, "document_sha256"),
        created_audit_sequence=created_audit_sequence,
        document_bytes=document_bytes,
    )
    if (
        metadata.document_rowid <= 0
        or metadata.version <= 0
        or metadata.complete not in (0, 1)
        or metadata.created_audit_sequence < 0
        or not all(
            _is_sha256(value)
            for value in (
                metadata.manifest_id,
                metadata.pack_input_sha256,
                metadata.closure_input_sha256,
                metadata.document_sha256,
            )
        )
    ):
        _fail(M6SQLiteEvidencePackDocumentFailureCode.INDEX_BINDING_MISMATCH)
    return metadata


def _require_metadata_binding(
    metadata: _StoredEvidencePackMetadata,
    *,
    run_id: str,
    manifest_id: str,
    selected_case_binding: M6UpgradeCandidateCaseBinding,
    pack: EvidencePack,
    expected_document_sha256: str,
    expected_document_bytes: int,
    expected_rowid: int | None = None,
    expected_created_audit_sequence: int | None = None,
) -> None:
    if metadata.run_id != run_id or metadata.manifest_id != manifest_id:
        _fail(M6SQLiteEvidencePackDocumentFailureCode.SCOPE_MISMATCH)
    if (
        metadata.pack_id != pack.pack_id
        or metadata.case_id != selected_case_binding.case_id
        or metadata.version != pack.version
        or metadata.complete != int(pack.complete)
        or metadata.pack_input_sha256 != pack.pack_input_sha256
        or metadata.closure_input_sha256 != pack.closure_input_sha256
        or metadata.document_sha256 != expected_document_sha256
        or metadata.document_bytes != expected_document_bytes
        or metadata.created_audit_sequence > selected_case_binding.case_audit_sequence
        or (expected_rowid is not None and metadata.document_rowid != expected_rowid)
        or (
            expected_created_audit_sequence is not None
            and metadata.created_audit_sequence != expected_created_audit_sequence
        )
    ):
        _fail(M6SQLiteEvidencePackDocumentFailureCode.INDEX_BINDING_MISMATCH)


def _read_planned_row(
    connection: M6SQLiteReadSession,
    plan: M6SQLiteEvidencePackPhysicalPlan,
) -> sqlite3.Row:
    pack = plan.pack_authority
    rows = _rows(
        connection,
        """
        SELECT rowid AS document_rowid,
               run_id, pack_id, case_id, manifest_id, version, complete,
               pack_input_sha256, closure_input_sha256, pack_json,
               document_sha256, created_audit_sequence
        FROM evidence_packs
        WHERE rowid = ? AND run_id = ? AND pack_id = ?
        """,
        (plan.document_rowid, pack.run_id, pack.pack_id),
        limit=MAX_M6_SQLITE_EVIDENCE_PACK_ROWS,
    )
    if not rows:
        _fail(M6SQLiteEvidencePackDocumentFailureCode.DOCUMENT_NOT_FOUND)
    if len(rows) != 1:
        _fail(M6SQLiteEvidencePackDocumentFailureCode.ROW_LIMIT_EXCEEDED)
    return rows[0]


def _decode_evidence_pack(canonical_document: str) -> EvidencePack:
    try:
        pack = EvidencePack.model_validate_json(canonical_document)
    except (TypeError, ValueError, ValidationError, UnicodeError):
        _fail(M6SQLiteEvidencePackDocumentFailureCode.DOCUMENT_INVALID)
    if canonical_json(pack.model_dump(mode="json")) != canonical_document:
        _fail(M6SQLiteEvidencePackDocumentFailureCode.DOCUMENT_INVALID)
    return pack


def plan_m6_sqlite_evidence_pack_physical_identity(
    *,
    connection: M6SQLiteReadSession,
    expected_run_id: str,
    expected_manifest_id: str,
    selected_case_authority: M6SQLiteCaseAuthorityDocument,
    pack_id: str,
) -> M6SQLiteEvidencePackPhysicalPlan:
    """Plan one selected-Case EvidencePack without reading independent JSON."""

    controlled, run_id, manifest_id, authority, pack = _validated_plan_arguments(
        connection,
        expected_run_id,
        expected_manifest_id,
        selected_case_authority,
        pack_id,
    )
    try:
        expected_canonical_document = canonical_json(pack.model_dump(mode="json"))
        expected_document_bytes = len(expected_canonical_document.encode("utf-8"))
        if expected_document_bytes > MAX_M6_SQLITE_EVIDENCE_PACK_DOCUMENT_BYTES:
            _fail(M6SQLiteEvidencePackDocumentFailureCode.DOCUMENT_TOO_LARGE)
        _require_scope(controlled, run_id, manifest_id)
        row, document_bytes = _preflight_row(controlled, run_id, pack.pack_id)
        metadata = _stored_metadata(row, document_bytes)
        expected_document_sha256 = _sha256(expected_canonical_document)
        _require_metadata_binding(
            metadata,
            run_id=run_id,
            manifest_id=manifest_id,
            selected_case_binding=authority.candidate_case_binding,
            pack=pack,
            expected_document_sha256=expected_document_sha256,
            expected_document_bytes=expected_document_bytes,
        )
        planned_ref = M6UpgradePhysicalArtifactRef(
            source=M6UpgradePhysicalArtifactSource.M2_EVIDENCE,
            kind=M6UpgradePhysicalArtifactKind.EVIDENCE_PACK,
            artifact_id=pack.pack_id,
            container_id=None,
            document_sha256=expected_document_sha256,
            content_sha256=expected_document_sha256,
            size_bytes=expected_document_bytes,
        )
        plan = M6SQLiteEvidencePackPhysicalPlan(
            selected_case_binding=authority.candidate_case_binding,
            pack_authority=pack,
            expected_canonical_document=expected_canonical_document,
            document_rowid=metadata.document_rowid,
            created_audit_sequence=metadata.created_audit_sequence,
            planned_artifact_ref=planned_ref,
        )
        _require_active_transaction(controlled)
        return plan
    except M6SQLiteEvidencePackDocumentError as error:
        raise error from None
    except (sqlite3.Error, M6LiveReadCutError, KeyError, IndexError):
        _fail(M6SQLiteEvidencePackDocumentFailureCode.DATABASE_REJECTED)
    except UnicodeError:
        _fail(M6SQLiteEvidencePackDocumentFailureCode.DOCUMENT_INVALID)


def resolve_m6_sqlite_evidence_pack_physical_plan(
    *,
    connection: M6SQLiteReadSession,
    physical_plan: M6SQLiteEvidencePackPhysicalPlan,
) -> M6SQLiteCanonicalPhysicalDocument:
    """Read and exact-match independent pack JSON after budget admission."""

    controlled, plan = _validated_resolve_arguments(connection, physical_plan)
    pack = plan.pack_authority
    try:
        _require_scope(controlled, pack.run_id, pack.manifest_id)
        row = _read_planned_row(controlled, plan)
        canonical_document = _document_text(row, "pack_json")
        actual_document_bytes = len(canonical_document.encode("utf-8"))
        if actual_document_bytes > MAX_M6_SQLITE_EVIDENCE_PACK_DOCUMENT_BYTES:
            _fail(M6SQLiteEvidencePackDocumentFailureCode.DOCUMENT_TOO_LARGE)
        if canonical_document != plan.expected_canonical_document:
            _fail(M6SQLiteEvidencePackDocumentFailureCode.DOCUMENT_INVALID)
        metadata = _stored_metadata(row, actual_document_bytes)
        _require_metadata_binding(
            metadata,
            run_id=pack.run_id,
            manifest_id=pack.manifest_id,
            selected_case_binding=plan.selected_case_binding,
            pack=pack,
            expected_document_sha256=plan.planned_artifact_ref.document_sha256,
            expected_document_bytes=plan.planned_artifact_ref.size_bytes,
            expected_rowid=plan.document_rowid,
            expected_created_audit_sequence=plan.created_audit_sequence,
        )
        decoded = _decode_evidence_pack(canonical_document)
        if decoded != pack:
            _fail(M6SQLiteEvidencePackDocumentFailureCode.DOCUMENT_INVALID)
        actual_sha256 = _sha256(canonical_document)
        resolved_ref = M6UpgradePhysicalArtifactRef(
            source=M6UpgradePhysicalArtifactSource.M2_EVIDENCE,
            kind=M6UpgradePhysicalArtifactKind.EVIDENCE_PACK,
            artifact_id=decoded.pack_id,
            container_id=None,
            document_sha256=actual_sha256,
            content_sha256=actual_sha256,
            size_bytes=actual_document_bytes,
        )
        if resolved_ref != plan.planned_artifact_ref:
            _fail(M6SQLiteEvidencePackDocumentFailureCode.PHYSICAL_PLAN_INVALID)
        result = M6SQLiteCanonicalPhysicalDocument(
            artifact_ref=resolved_ref,
            document=decoded,
            canonical_document=canonical_document,
        )
        _require_active_transaction(controlled)
        return result
    except M6SQLiteEvidencePackDocumentError as error:
        raise error from None
    except (sqlite3.Error, M6LiveReadCutError, KeyError, IndexError):
        _fail(M6SQLiteEvidencePackDocumentFailureCode.DATABASE_REJECTED)
    except UnicodeError:
        _fail(M6SQLiteEvidencePackDocumentFailureCode.DOCUMENT_INVALID)


__all__ = [
    "MAX_M6_SQLITE_EVIDENCE_PACK_DOCUMENT_BYTES",
    "MAX_M6_SQLITE_EVIDENCE_PACK_ROWS",
    "M6SQLiteEvidencePackDocumentError",
    "M6SQLiteEvidencePackDocumentFailureCode",
    "M6SQLiteEvidencePackPhysicalPlan",
    "plan_m6_sqlite_evidence_pack_physical_identity",
    "resolve_m6_sqlite_evidence_pack_physical_plan",
]
