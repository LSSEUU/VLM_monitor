"""Seal terminal M6 Gate Crop authority inside one live SQLite read cut.

The terminal builder resolves every selected EvidencePack body before any Raw
model response is opened.  This module consumes those already-resolved
documents, rechecks their normalized SQLite rows, then reads the immutable Crop
link documents and current ``media_assets`` rows from the same ``M6LiveReader``
snapshot.  Only after every row has passed does it call the injected physical
Crop verifier.  It never opens a repository or another SQLite connection.
"""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass
from enum import StrEnum
from typing import NoReturn, cast

from pydantic import ValidationError

from labcourt.application.m6_source_authority_sealing import (
    M6SealedGateSource,
    M6SourceAuthoritySealingError,
    seal_m6_gate_current_closures,
)
from labcourt.contracts.audit import AuditEntry
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case
from labcourt.contracts.enums import (
    ArtifactKind,
    MediaAvailability,
    VerificationStatus,
)
from labcourt.contracts.evidence import Crop, EvidencePack
from labcourt.contracts.m6_source_authority import (
    MAX_M6_GATE_CURRENT_CLOSURES_PER_CASE,
)
from labcourt.contracts.m6_upgrade_execution_ledger import (
    M6UpgradeCandidateCaseBinding,
)
from labcourt.contracts.storage import ArtifactRef, ArtifactVerification, ClosureReport
from labcourt.exceptions import ContractViolation
from labcourt.ports.evidence_repository import EvidenceVerifier
from labcourt.ports.m6_source_authority_sealing import (
    M6CurrentPackObservation,
    M6GateSourceObservation,
)

from ._sqlite_m6_live_read_cut import (
    M6LiveReadCutError,
    M6LiveReader,
)
from ._sqlite_m6_upgrade_case_document import M6SQLiteCaseAuthorityDocument
from ._sqlite_m6_upgrade_evidence_pack_document import (
    M6SQLiteEvidencePackPhysicalPlan,
)
from ._sqlite_m6_upgrade_physical_documents import (
    M6SQLiteCanonicalPhysicalDocument,
)

MAX_M6_SQLITE_GATE_CURRENT_CROPS_PER_PACK = 256
MAX_M6_SQLITE_GATE_CURRENT_CROP_DOCUMENT_BYTES = 1024 * 1024
MAX_M6_SQLITE_GATE_CURRENT_TOTAL_CROPS = (
    MAX_M6_GATE_CURRENT_CLOSURES_PER_CASE * MAX_M6_SQLITE_GATE_CURRENT_CROPS_PER_PACK
)


class M6SQLiteGateCurrentSourceFailureCode(StrEnum):
    """Payload-free failures at the same-snapshot Gate Crop boundary."""

    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    TRANSACTION_REQUIRED = "TRANSACTION_REQUIRED"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"
    AUDIT_HEAD_MISMATCH = "AUDIT_HEAD_MISMATCH"
    REVIEW_PACK_COVERAGE_MISMATCH = "REVIEW_PACK_COVERAGE_MISMATCH"
    PACK_AUTHORITY_MISMATCH = "PACK_AUTHORITY_MISMATCH"
    CROP_AUTHORITY_MISMATCH = "CROP_AUTHORITY_MISMATCH"
    CROP_DOCUMENT_TOO_LARGE = "CROP_DOCUMENT_TOO_LARGE"
    CROP_DOCUMENT_INVALID = "CROP_DOCUMENT_INVALID"
    CURRENT_MEDIA_VERIFICATION_FAILED = "CURRENT_MEDIA_VERIFICATION_FAILED"
    SEALING_REJECTED = "SEALING_REJECTED"
    DATABASE_REJECTED = "DATABASE_REJECTED"


class M6SQLiteGateCurrentSourceError(ContractViolation):
    """The terminal Gate current source could not be sealed exactly."""

    def __init__(self, reason_code: M6SQLiteGateCurrentSourceFailureCode) -> None:
        if not isinstance(reason_code, M6SQLiteGateCurrentSourceFailureCode):
            raise TypeError("reason_code must be an M6 SQLite Gate current-source code")
        self.reason_code = reason_code
        super().__init__(f"M6 SQLite Gate current source failed: {reason_code.value}")


@dataclass(frozen=True, slots=True)
class _StoredCropAuthority:
    pack_key: tuple[str, int]
    role: str
    ordinal: int
    rowid: int
    crop_document_sha256: str
    crop_document_bytes: int
    crop: Crop


@dataclass(frozen=True, slots=True)
class _ReviewedPackAuthority:
    pack: EvidencePack
    crops: tuple[_StoredCropAuthority, ...]


def _fail(reason_code: M6SQLiteGateCurrentSourceFailureCode) -> NoReturn:
    raise M6SQLiteGateCurrentSourceError(reason_code) from None


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _require_active_transaction(connection: M6LiveReader) -> None:
    try:
        in_transaction = connection.in_transaction
    except (sqlite3.Error, RuntimeError, M6LiveReadCutError):
        _fail(M6SQLiteGateCurrentSourceFailureCode.DATABASE_REJECTED)
    if type(in_transaction) is not bool:
        _fail(M6SQLiteGateCurrentSourceFailureCode.DATABASE_REJECTED)
    if not in_transaction:
        _fail(M6SQLiteGateCurrentSourceFailureCode.TRANSACTION_REQUIRED)


def _rows(
    connection: M6LiveReader,
    sql: str,
    parameters: tuple[object, ...],
    *,
    limit: int,
) -> tuple[sqlite3.Row, ...]:
    cursor = None
    try:
        cursor = connection.execute(sql, parameters)
        return tuple(cursor.fetchmany(limit + 1))
    except (sqlite3.Error, RuntimeError, M6LiveReadCutError):
        _fail(M6SQLiteGateCurrentSourceFailureCode.DATABASE_REJECTED)
    finally:
        if cursor is not None:
            try:
                cursor.close()
            except (sqlite3.Error, RuntimeError, M6LiveReadCutError):
                _fail(M6SQLiteGateCurrentSourceFailureCode.DATABASE_REJECTED)


def _row_text(row: sqlite3.Row, column: str) -> str:
    value = row[column]
    if not isinstance(value, str):
        _fail(M6SQLiteGateCurrentSourceFailureCode.CROP_AUTHORITY_MISMATCH)
    return value


def _row_optional_text(row: sqlite3.Row, column: str) -> str | None:
    value = row[column]
    if value is not None and not isinstance(value, str):
        _fail(M6SQLiteGateCurrentSourceFailureCode.CROP_AUTHORITY_MISMATCH)
    return value


def _row_integer(row: sqlite3.Row, column: str) -> int:
    value = row[column]
    if type(value) is not int:
        _fail(M6SQLiteGateCurrentSourceFailureCode.CROP_AUTHORITY_MISMATCH)
    return value


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
        case_document = canonical_json(case.model_dump(mode="json"))
        audit_document = canonical_json(audit.model_dump(mode="json"))
    except (AttributeError, TypeError, ValueError, ValidationError, UnicodeError):
        return False
    case_sha256 = _sha256(case_document)
    return (
        controlled_binding == binding
        and controlled_case == case
        and controlled_audit == audit
        and case_document == authority.canonical_case_document
        and audit_document == authority.canonical_audit_document
        and case.case_id == binding.case_id
        and case_sha256 == binding.case_document_sha256
        and audit.sequence == binding.case_audit_sequence
        and audit.entry_hash == binding.case_audit_entry_hash
        and audit.after_sha256 == case_sha256
    )


def _validated_arguments(
    connection: object,
    selected_case_authority: object,
    evidence_pack_plans: object,
    resolved_evidence_packs: object,
    expected_audit_head_sequence: object,
    expected_audit_head_hash: object,
    crop_verifier: object,
) -> tuple[
    M6LiveReader,
    M6SQLiteCaseAuthorityDocument,
    tuple[M6SQLiteEvidencePackPhysicalPlan, ...],
    tuple[M6SQLiteCanonicalPhysicalDocument, ...],
    int,
    str,
    EvidenceVerifier,
]:
    if (
        type(connection) is not M6LiveReader
        or type(selected_case_authority) is not M6SQLiteCaseAuthorityDocument
        or not isinstance(evidence_pack_plans, tuple)
        or not isinstance(resolved_evidence_packs, tuple)
        or type(expected_audit_head_sequence) is not int
        or expected_audit_head_sequence < -1
        or not _is_sha256(expected_audit_head_hash)
        or not callable(getattr(crop_verifier, "verify_crop", None))
    ):
        _fail(M6SQLiteGateCurrentSourceFailureCode.INVALID_ARGUMENT)
    if any(type(item) is not M6SQLiteEvidencePackPhysicalPlan for item in evidence_pack_plans):
        _fail(M6SQLiteGateCurrentSourceFailureCode.INVALID_ARGUMENT)
    if any(type(item) is not M6SQLiteCanonicalPhysicalDocument for item in resolved_evidence_packs):
        _fail(M6SQLiteGateCurrentSourceFailureCode.INVALID_ARGUMENT)
    if (
        len(evidence_pack_plans) > MAX_M6_GATE_CURRENT_CLOSURES_PER_CASE
        or len(resolved_evidence_packs) > MAX_M6_GATE_CURRENT_CLOSURES_PER_CASE
    ):
        _fail(M6SQLiteGateCurrentSourceFailureCode.REVIEW_PACK_COVERAGE_MISMATCH)
    controlled_reader = connection
    authority = selected_case_authority
    _require_active_transaction(controlled_reader)
    if not _case_authority_is_consistent(authority):
        _fail(M6SQLiteGateCurrentSourceFailureCode.INVALID_ARGUMENT)
    return (
        controlled_reader,
        authority,
        cast(tuple[M6SQLiteEvidencePackPhysicalPlan, ...], evidence_pack_plans),
        cast(tuple[M6SQLiteCanonicalPhysicalDocument, ...], resolved_evidence_packs),
        expected_audit_head_sequence,
        cast(str, expected_audit_head_hash),
        cast(EvidenceVerifier, crop_verifier),
    )


def _require_audit_head(
    connection: M6LiveReader,
    authority: M6SQLiteCaseAuthorityDocument,
    expected_sequence: int,
    expected_hash: str,
) -> None:
    rows = _rows(
        connection,
        """
        SELECT manifest_id, audit_head_sequence, audit_head_hash
        FROM runs
        WHERE run_id = ?
        """,
        (authority.case.run_id,),
        limit=1,
    )
    if len(rows) != 1:
        _fail(M6SQLiteGateCurrentSourceFailureCode.SCOPE_MISMATCH)
    row = rows[0]
    manifest_id = row["manifest_id"]
    sequence = row["audit_head_sequence"]
    head_hash = row["audit_head_hash"]
    if not isinstance(manifest_id, str) or manifest_id != authority.case.manifest_id:
        _fail(M6SQLiteGateCurrentSourceFailureCode.SCOPE_MISMATCH)
    if type(sequence) is not int or not isinstance(head_hash, str):
        _fail(M6SQLiteGateCurrentSourceFailureCode.AUDIT_HEAD_MISMATCH)
    if sequence != expected_sequence or head_hash != expected_hash:
        _fail(M6SQLiteGateCurrentSourceFailureCode.AUDIT_HEAD_MISMATCH)


def _reviewed_pack_keys(case: Case) -> tuple[tuple[str, int], ...]:
    keys = tuple(
        sorted(
            {
                (review.evidence_pack_id, review.evidence_pack_version)
                for review in case.procedural_reviews
            }
        )
    )
    if not keys or len(keys) > MAX_M6_GATE_CURRENT_CLOSURES_PER_CASE:
        _fail(M6SQLiteGateCurrentSourceFailureCode.REVIEW_PACK_COVERAGE_MISMATCH)
    return keys


def _resolved_pack_map(
    authority: M6SQLiteCaseAuthorityDocument,
    plans: tuple[M6SQLiteEvidencePackPhysicalPlan, ...],
    resolved_documents: tuple[M6SQLiteCanonicalPhysicalDocument, ...],
) -> dict[tuple[str, int], tuple[M6SQLiteEvidencePackPhysicalPlan, EvidencePack]]:
    expected_keys = set(_reviewed_pack_keys(authority.case))
    case_packs = {(pack.pack_id, pack.version): pack for pack in authority.case.evidence_packs}
    if len(case_packs) != len(authority.case.evidence_packs) or not expected_keys.issubset(
        case_packs
    ):
        _fail(M6SQLiteGateCurrentSourceFailureCode.REVIEW_PACK_COVERAGE_MISMATCH)

    plan_map: dict[tuple[str, int], M6SQLiteEvidencePackPhysicalPlan] = {}
    for plan in plans:
        pack = plan.pack_authority
        key = (pack.pack_id, pack.version)
        if key in plan_map:
            _fail(M6SQLiteGateCurrentSourceFailureCode.REVIEW_PACK_COVERAGE_MISMATCH)
        plan_map[key] = plan
    document_map: dict[tuple[str, int], M6SQLiteCanonicalPhysicalDocument] = {}
    for document in resolved_documents:
        if type(document.document) is not EvidencePack:
            _fail(M6SQLiteGateCurrentSourceFailureCode.PACK_AUTHORITY_MISMATCH)
        pack = document.document
        key = (pack.pack_id, pack.version)
        if key in document_map:
            _fail(M6SQLiteGateCurrentSourceFailureCode.REVIEW_PACK_COVERAGE_MISMATCH)
        document_map[key] = document
    if set(plan_map) != expected_keys or set(document_map) != expected_keys:
        _fail(M6SQLiteGateCurrentSourceFailureCode.REVIEW_PACK_COVERAGE_MISMATCH)

    resolved: dict[
        tuple[str, int],
        tuple[M6SQLiteEvidencePackPhysicalPlan, EvidencePack],
    ] = {}
    for key in sorted(expected_keys):
        plan = plan_map[key]
        document = document_map[key]
        case_pack = case_packs[key]
        canonical_document = canonical_json(case_pack.model_dump(mode="json"))
        if (
            plan.selected_case_binding != authority.candidate_case_binding
            or plan.pack_authority != case_pack
            or document.document != case_pack
            or document.canonical_document != canonical_document
            or plan.expected_canonical_document != canonical_document
            or document.artifact_ref != plan.planned_artifact_ref
            or document.artifact_ref.artifact_id != case_pack.pack_id
            or document.artifact_ref.document_sha256 != _sha256(canonical_document)
            or document.artifact_ref.size_bytes != len(canonical_document.encode("utf-8"))
        ):
            _fail(M6SQLiteGateCurrentSourceFailureCode.PACK_AUTHORITY_MISMATCH)
        if len(case_pack.crops) > MAX_M6_SQLITE_GATE_CURRENT_CROPS_PER_PACK:
            _fail(M6SQLiteGateCurrentSourceFailureCode.REVIEW_PACK_COVERAGE_MISMATCH)
        resolved[key] = plan, case_pack
    if sum(len(pack.crops) for _, pack in resolved.values()) > (
        MAX_M6_SQLITE_GATE_CURRENT_TOTAL_CROPS
    ):
        _fail(M6SQLiteGateCurrentSourceFailureCode.REVIEW_PACK_COVERAGE_MISMATCH)
    return resolved


def _require_pack_row(
    connection: M6LiveReader,
    authority: M6SQLiteCaseAuthorityDocument,
    plan: M6SQLiteEvidencePackPhysicalPlan,
    pack: EvidencePack,
) -> None:
    rows = _rows(
        connection,
        """
        SELECT rowid AS document_rowid,
               case_id, manifest_id, version, complete,
               pack_input_sha256, closure_input_sha256,
               document_sha256, created_audit_sequence,
               length(CAST(pack_json AS BLOB)) AS document_bytes
        FROM evidence_packs
        WHERE rowid = ? AND run_id = ? AND pack_id = ?
        """,
        (plan.document_rowid, pack.run_id, pack.pack_id),
        limit=1,
    )
    if len(rows) != 1:
        _fail(M6SQLiteGateCurrentSourceFailureCode.PACK_AUTHORITY_MISMATCH)
    row = rows[0]
    canonical_document = canonical_json(pack.model_dump(mode="json"))
    values = (
        row["document_rowid"],
        row["case_id"],
        row["manifest_id"],
        row["version"],
        row["complete"],
        row["pack_input_sha256"],
        row["closure_input_sha256"],
        row["document_sha256"],
        row["created_audit_sequence"],
        row["document_bytes"],
    )
    if (
        type(values[0]) is not int
        or not isinstance(values[1], str)
        or not isinstance(values[2], str)
        or type(values[3]) is not int
        or type(values[4]) is not int
        or not isinstance(values[5], str)
        or not isinstance(values[6], str)
        or not isinstance(values[7], str)
        or type(values[8]) is not int
        or type(values[9]) is not int
        or values[0] != plan.document_rowid
        or values[1] != pack.case_id
        or values[2] != pack.manifest_id
        or values[3] != pack.version
        or values[4] != int(pack.complete)
        or values[5] != pack.pack_input_sha256
        or values[6] != pack.closure_input_sha256
        or values[7] != _sha256(canonical_document)
        or values[8] != plan.created_audit_sequence
        or values[8] > authority.candidate_case_binding.case_audit_sequence
        or values[9] != len(canonical_document.encode("utf-8"))
    ):
        _fail(M6SQLiteGateCurrentSourceFailureCode.PACK_AUTHORITY_MISMATCH)


def _expected_crop_positions(pack: EvidencePack) -> dict[tuple[str, int], Crop]:
    return {
        (role, ordinal): crop
        for role, crops in (
            ("panorama", pack.panorama_crops),
            ("subject", pack.subject_crops),
            ("focus", pack.focus_crops),
            ("temporal", pack.temporal_crops),
        )
        for ordinal, crop in enumerate(crops)
    }


def _read_crop_metadata(
    connection: M6LiveReader,
    pack: EvidencePack,
) -> tuple[_StoredCropAuthority, ...]:
    expected = _expected_crop_positions(pack)
    rows = _rows(
        connection,
        """
        SELECT epc.rowid AS crop_link_rowid,
               epc.crop_id, epc.media_sha256, epc.role, epc.ordinal,
               epc.document_sha256 AS crop_document_sha256,
               length(CAST(epc.crop_json AS BLOB)) AS crop_document_bytes,
               ma.run_id AS media_run_id,
               ma.manifest_id AS media_manifest_id,
               ma.local_path, ma.availability, ma.pixel_sha256,
               ma.width, ma.height, ma.size_bytes, ma.media_type,
               ma.encoding_version
        FROM evidence_pack_crops AS epc
        LEFT JOIN media_assets AS ma
          ON ma.run_id = epc.run_id AND ma.media_sha256 = epc.media_sha256
        WHERE epc.run_id = ? AND epc.pack_id = ?
        ORDER BY epc.role, epc.ordinal, epc.crop_id
        """,
        (pack.run_id, pack.pack_id),
        limit=len(expected),
    )
    if len(rows) != len(expected):
        _fail(M6SQLiteGateCurrentSourceFailureCode.CROP_AUTHORITY_MISMATCH)

    observed: dict[tuple[str, int], _StoredCropAuthority] = {}
    crop_ids: set[str] = set()
    for row in rows:
        role = _row_text(row, "role")
        ordinal = _row_integer(row, "ordinal")
        position = (role, ordinal)
        crop = expected.get(position)
        if crop is None or position in observed:
            _fail(M6SQLiteGateCurrentSourceFailureCode.CROP_AUTHORITY_MISMATCH)
        rowid = _row_integer(row, "crop_link_rowid")
        crop_document_sha256 = _row_text(row, "crop_document_sha256")
        crop_document_bytes = _row_integer(row, "crop_document_bytes")
        if crop_document_bytes > MAX_M6_SQLITE_GATE_CURRENT_CROP_DOCUMENT_BYTES:
            _fail(M6SQLiteGateCurrentSourceFailureCode.CROP_DOCUMENT_TOO_LARGE)
        canonical_crop = canonical_json(crop.model_dump(mode="json"))
        crop_id = _row_text(row, "crop_id")
        if crop_id in crop_ids:
            _fail(M6SQLiteGateCurrentSourceFailureCode.CROP_AUTHORITY_MISMATCH)
        crop_ids.add(crop_id)
        if (
            rowid <= 0
            or crop_id != crop.crop_id
            or _row_text(row, "media_sha256") != crop.media_sha256
            or crop_document_sha256 != _sha256(canonical_crop)
            or crop_document_bytes != len(canonical_crop.encode("utf-8"))
            or _row_text(row, "media_run_id") != pack.run_id
            or _row_text(row, "media_manifest_id") != pack.manifest_id
            or _row_optional_text(row, "local_path") != crop.local_path
            or _row_text(row, "availability") != crop.availability.value
            or _row_text(row, "availability") != MediaAvailability.AVAILABLE.value
            or _row_text(row, "pixel_sha256") != crop.pixel_sha256
            or _row_integer(row, "width") != crop.output_width
            or _row_integer(row, "height") != crop.output_height
            or _row_integer(row, "size_bytes") != crop.size_bytes
            or _row_text(row, "media_type") != crop.media_type.value
            or _row_text(row, "encoding_version") != crop.encoding_version
        ):
            _fail(M6SQLiteGateCurrentSourceFailureCode.CROP_AUTHORITY_MISMATCH)
        observed[position] = _StoredCropAuthority(
            pack_key=(pack.pack_id, pack.version),
            role=role,
            ordinal=ordinal,
            rowid=rowid,
            crop_document_sha256=crop_document_sha256,
            crop_document_bytes=crop_document_bytes,
            crop=crop,
        )
    return tuple(observed[position] for position in sorted(observed))


def _require_crop_documents(
    connection: M6LiveReader,
    reviewed_packs: tuple[_ReviewedPackAuthority, ...],
) -> None:
    for reviewed in reviewed_packs:
        for stored in reviewed.crops:
            rows = _rows(
                connection,
                """
                SELECT crop_json, document_sha256
                FROM evidence_pack_crops
                WHERE rowid = ? AND run_id = ? AND pack_id = ? AND crop_id = ?
                """,
                (
                    stored.rowid,
                    reviewed.pack.run_id,
                    reviewed.pack.pack_id,
                    stored.crop.crop_id,
                ),
                limit=1,
            )
            if len(rows) != 1:
                _fail(M6SQLiteGateCurrentSourceFailureCode.CROP_AUTHORITY_MISMATCH)
            raw = rows[0]["crop_json"]
            document_sha256 = rows[0]["document_sha256"]
            if not isinstance(raw, str) or not isinstance(document_sha256, str):
                _fail(M6SQLiteGateCurrentSourceFailureCode.CROP_DOCUMENT_INVALID)
            try:
                raw_bytes = raw.encode("utf-8")
            except UnicodeError:
                _fail(M6SQLiteGateCurrentSourceFailureCode.CROP_DOCUMENT_INVALID)
            if len(raw_bytes) > MAX_M6_SQLITE_GATE_CURRENT_CROP_DOCUMENT_BYTES:
                _fail(M6SQLiteGateCurrentSourceFailureCode.CROP_DOCUMENT_TOO_LARGE)
            if (
                len(raw_bytes) != stored.crop_document_bytes
                or _sha256(raw) != stored.crop_document_sha256
                or document_sha256 != stored.crop_document_sha256
            ):
                _fail(M6SQLiteGateCurrentSourceFailureCode.CROP_DOCUMENT_INVALID)
            try:
                decoded = Crop.model_validate_json(raw)
            except (TypeError, ValueError, ValidationError, UnicodeError):
                _fail(M6SQLiteGateCurrentSourceFailureCode.CROP_DOCUMENT_INVALID)
            if canonical_json(decoded.model_dump(mode="json")) != raw or decoded != stored.crop:
                _fail(M6SQLiteGateCurrentSourceFailureCode.CROP_DOCUMENT_INVALID)


def _verification_matches_crop(
    verification: ArtifactVerification,
    crop: Crop,
) -> bool:
    return (
        verification.artifact_ref == ArtifactRef(kind=ArtifactKind.CROP, artifact_id=crop.crop_id)
        and verification.status == VerificationStatus.CURRENT_MEDIA_VERIFIED
        and verification.availability == MediaAvailability.AVAILABLE
        and verification.media_type == crop.media_type
        and verification.expected_source_pixel_sha256 == crop.source_media_sha256
        and verification.actual_source_pixel_sha256 is None
        and verification.expected_output_pixel_sha256 == crop.pixel_sha256
        and verification.actual_output_pixel_sha256 == crop.pixel_sha256
        and verification.expected_media_sha256 == crop.media_sha256
        and verification.actual_media_sha256 == crop.media_sha256
        and verification.expected_width == crop.output_width
        and verification.actual_width == crop.output_width
        and verification.expected_height == crop.output_height
        and verification.actual_height == crop.output_height
        and verification.expected_size_bytes == crop.size_bytes
        and verification.actual_size_bytes == crop.size_bytes
        and verification.reason_code is None
    )


def _verify_current_crops(
    reviewed_packs: tuple[_ReviewedPackAuthority, ...],
    crop_verifier: EvidenceVerifier,
) -> dict[str, ArtifactVerification]:
    crop_by_id: dict[str, Crop] = {}
    for reviewed in reviewed_packs:
        for crop in sorted(reviewed.pack.crops, key=lambda item: item.crop_id):
            previous = crop_by_id.get(crop.crop_id)
            if previous is not None and previous != crop:
                _fail(M6SQLiteGateCurrentSourceFailureCode.CROP_AUTHORITY_MISMATCH)
            crop_by_id[crop.crop_id] = crop

    verified: dict[str, ArtifactVerification] = {}
    for crop_id in sorted(crop_by_id):
        crop = crop_by_id[crop_id]
        try:
            raw_verification = crop_verifier.verify_crop(crop)
            if not isinstance(raw_verification, ArtifactVerification):
                _fail(M6SQLiteGateCurrentSourceFailureCode.CURRENT_MEDIA_VERIFICATION_FAILED)
            verification = ArtifactVerification.model_validate(
                raw_verification.model_dump(mode="json", exclude_computed_fields=True)
            )
        except M6SQLiteGateCurrentSourceError:
            raise
        except Exception:
            _fail(M6SQLiteGateCurrentSourceFailureCode.CURRENT_MEDIA_VERIFICATION_FAILED)
        if verification != raw_verification or not _verification_matches_crop(verification, crop):
            _fail(M6SQLiteGateCurrentSourceFailureCode.CURRENT_MEDIA_VERIFICATION_FAILED)
        verified[crop_id] = verification
    return verified


def _current_closure(pack: EvidencePack) -> ClosureReport:
    root = ArtifactRef(kind=ArtifactKind.EVIDENCE_PACK, artifact_id=pack.pack_id)
    refs = {ref.sort_key: ref for ref in (*pack.expected_closure_refs(), root)}
    try:
        return ClosureReport(
            run_id=pack.run_id,
            root_ref=root,
            manifest_id=pack.manifest_id,
            input_sha256=pack.closure_input_sha256,
            checked_refs=tuple(refs[key] for key in sorted(refs)),
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6SQLiteGateCurrentSourceFailureCode.SEALING_REJECTED)


def seal_m6_sqlite_gate_current_source(
    *,
    connection: M6LiveReader,
    selected_case_authority: M6SQLiteCaseAuthorityDocument,
    evidence_pack_plans: tuple[M6SQLiteEvidencePackPhysicalPlan, ...],
    resolved_evidence_packs: tuple[M6SQLiteCanonicalPhysicalDocument, ...],
    expected_audit_head_sequence: int,
    expected_audit_head_hash: str,
    crop_verifier: EvidenceVerifier,
) -> M6SealedGateSource:
    """Seal reviewed-pack current Crop receipts without leaving the B snapshot."""

    (
        reader,
        authority,
        plans,
        resolved_documents,
        audit_head_sequence,
        audit_head_hash,
        verifier,
    ) = _validated_arguments(
        connection,
        selected_case_authority,
        evidence_pack_plans,
        resolved_evidence_packs,
        expected_audit_head_sequence,
        expected_audit_head_hash,
        crop_verifier,
    )
    _require_audit_head(
        reader,
        authority,
        audit_head_sequence,
        audit_head_hash,
    )
    resolved = _resolved_pack_map(authority, plans, resolved_documents)

    reviewed_packs: list[_ReviewedPackAuthority] = []
    for key in sorted(resolved):
        plan, pack = resolved[key]
        _require_pack_row(reader, authority, plan, pack)
        reviewed_packs.append(
            _ReviewedPackAuthority(
                pack=pack,
                crops=_read_crop_metadata(reader, pack),
            )
        )
    ordered_reviewed_packs = tuple(reviewed_packs)
    _require_crop_documents(reader, ordered_reviewed_packs)

    verifications = _verify_current_crops(ordered_reviewed_packs, verifier)
    observations = tuple(
        M6CurrentPackObservation(
            pack=reviewed.pack,
            current_closure=_current_closure(reviewed.pack),
            crop_verifications=tuple(
                sorted(
                    (verifications[crop.crop_id] for crop in reviewed.pack.crops),
                    key=lambda item: item.artifact_ref.sort_key,
                )
            ),
        )
        for reviewed in ordered_reviewed_packs
    )
    try:
        observation = M6GateSourceObservation(
            source_case=authority.case,
            source_case_revision=authority.candidate_case_binding.case_revision,
            source_case_document_sha256=authority.case_document_sha256,
            audit_head_sequence=audit_head_sequence,
            audit_head_hash=audit_head_hash,
            packs=observations,
        )
        sealed = seal_m6_gate_current_closures(observation=observation)
    except M6SourceAuthoritySealingError:
        _fail(M6SQLiteGateCurrentSourceFailureCode.SEALING_REJECTED)
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6SQLiteGateCurrentSourceFailureCode.SEALING_REJECTED)
    _require_active_transaction(reader)
    if (
        sealed.source_case != authority.case
        or sealed.source_case_revision != authority.candidate_case_binding.case_revision
        or sealed.source_case_document_sha256 != authority.case_document_sha256
        or sealed.audit_head_sequence != audit_head_sequence
        or sealed.audit_head_hash != audit_head_hash
    ):
        _fail(M6SQLiteGateCurrentSourceFailureCode.SEALING_REJECTED)
    return sealed


__all__ = [
    "MAX_M6_SQLITE_GATE_CURRENT_CROPS_PER_PACK",
    "MAX_M6_SQLITE_GATE_CURRENT_CROP_DOCUMENT_BYTES",
    "MAX_M6_SQLITE_GATE_CURRENT_TOTAL_CROPS",
    "M6SQLiteGateCurrentSourceError",
    "M6SQLiteGateCurrentSourceFailureCode",
    "seal_m6_sqlite_gate_current_source",
]
