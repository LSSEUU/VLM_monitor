"""Canonical input, row, and slot primitives for the M3 metadata planner."""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass
from typing import NoReturn

from pydantic import ValidationError

from labcourt.contracts.audit import AuditEntry
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case
from labcourt.contracts.m6_replay_locked import M6LockedModelCallLayer, M6LockedModelRole
from labcourt.contracts.m6_upgrade_execution_ledger import M6UpgradeCandidateCaseBinding
from labcourt.contracts.m6_upgrade_execution_observation import M6UpgradeObservedModelCall
from labcourt.contracts.m6_upgrade_physical import (
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactRef,
    M6UpgradePhysicalArtifactSource,
)
from labcourt.contracts.references import require_reference_token

from ._sqlite_m6_live_read_cut import M6LiveReader
from ._sqlite_m6_upgrade_case_document import M6SQLiteCaseAuthorityDocument
from ._sqlite_m6_upgrade_m3_model_plan import (
    MAX_M6_SQLITE_M3_MODEL_ROWS_PER_GROUP,
    M6SQLiteM3DocumentRoute,
    M6SQLiteM3DocumentSlot,
    M6SQLiteM3ModelDocumentFailureCode,
    _M6SQLiteM3MetadataFailure,
)
from ._sqlite_m6_upgrade_m3_model_rows import document_bytes

_SOURCE = M6UpgradePhysicalArtifactSource.M3_SCREENING_MODEL


def _fail(reason_code: M6SQLiteM3ModelDocumentFailureCode) -> NoReturn:
    raise _M6SQLiteM3MetadataFailure(reason_code)


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _text(row: sqlite3.Row, column: str) -> str:
    value = row[column]
    if not isinstance(value, str):
        _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    return value


def _sha256(row: sqlite3.Row, column: str) -> str:
    value = _text(row, column)
    if not _is_sha256(value):
        _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    return value


def _integer(row: sqlite3.Row, column: str, *, minimum: int = 0) -> int:
    value = row[column]
    if type(value) is not int or value < minimum:
        _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    return value


def _number(row: sqlite3.Row, column: str, *, minimum: float = 0.0) -> float:
    value = row[column]
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < minimum:
        _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    return float(value)


def _optional_text(row: sqlite3.Row, column: str) -> str | None:
    value = row[column]
    if value is not None and not isinstance(value, str):
        _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    return value


def _row_identity(row: sqlite3.Row, domain: str) -> str:
    values: list[list[object]] = []
    for key in row.keys():  # noqa: SIM118 - sqlite3.Row iterates values, not keys
        if key.endswith(("_document_type", "_document_bytes")):
            continue
        value = row[key]
        if value is not None and not isinstance(value, (str, int, float)):
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        values.append([key, value])
    try:
        payload = canonical_json(["m6-sqlite-m3-index", 1, domain, values])
    except (TypeError, ValueError, UnicodeError):
        _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _single(
    rows: tuple[sqlite3.Row, ...],
    *,
    missing: M6SQLiteM3ModelDocumentFailureCode = (
        M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH
    ),
) -> sqlite3.Row:
    if not rows:
        _fail(missing)
    if len(rows) != 1:
        _fail(M6SQLiteM3ModelDocumentFailureCode.ROW_LIMIT_EXCEEDED)
    return rows[0]


def _case_authority_is_consistent(authority: M6SQLiteCaseAuthorityDocument) -> bool:
    if (
        type(authority.candidate_case_binding) is not M6UpgradeCandidateCaseBinding
        or type(authority.case) is not Case
        or type(authority.audit_entry) is not AuditEntry
        or not isinstance(authority.canonical_case_document, str)
        or not isinstance(authority.canonical_audit_document, str)
    ):
        return False
    try:
        binding = M6UpgradeCandidateCaseBinding.model_validate(
            authority.candidate_case_binding.model_dump(
                mode="json",
                exclude_computed_fields=True,
            )
        )
        selected_case = Case.model_validate(
            authority.case.model_dump(mode="json", exclude_computed_fields=True)
        )
        audit = AuditEntry.model_validate(
            authority.audit_entry.model_dump(mode="json", exclude_computed_fields=True)
        )
        canonical_case = canonical_json(selected_case.model_dump(mode="json"))
        canonical_audit = canonical_json(audit.model_dump(mode="json"))
        case_sha256 = hashlib.sha256(canonical_case.encode("utf-8")).hexdigest()
    except (AttributeError, TypeError, ValueError, ValidationError, UnicodeError):
        return False
    return (
        binding == authority.candidate_case_binding
        and selected_case == authority.case
        and audit == authority.audit_entry
        and canonical_case == authority.canonical_case_document
        and canonical_audit == authority.canonical_audit_document
        and binding.case_id == selected_case.case_id
        and binding.case_document_sha256 == case_sha256
        and binding.case_audit_sequence == audit.sequence
        and binding.case_audit_entry_hash == audit.entry_hash
        and audit.after_sha256 == case_sha256
    )


def _active(connection: M6LiveReader) -> None:
    active = connection.in_transaction
    if type(active) is not bool:
        _fail(M6SQLiteM3ModelDocumentFailureCode.DATABASE_REJECTED)
    if not active:
        _fail(M6SQLiteM3ModelDocumentFailureCode.TRANSACTION_REQUIRED)


def _validated_arguments(
    connection: object,
    expected_run_id: object,
    expected_manifest_id: object,
    expected_model_manifest_id: object,
    selected_case_authority: object,
    observed_model_calls: object,
) -> tuple[
    M6LiveReader,
    str,
    str,
    str,
    M6SQLiteCaseAuthorityDocument,
    tuple[M6UpgradeObservedModelCall, ...],
]:
    if (
        type(connection) is not M6LiveReader
        or not isinstance(expected_run_id, str)
        or not _is_sha256(expected_manifest_id)
        or not _is_sha256(expected_model_manifest_id)
        or type(selected_case_authority) is not M6SQLiteCaseAuthorityDocument
        or type(observed_model_calls) is not tuple
    ):
        _fail(M6SQLiteM3ModelDocumentFailureCode.INVALID_ARGUMENT)
    assert isinstance(connection, M6LiveReader)
    assert isinstance(expected_run_id, str)
    assert isinstance(expected_manifest_id, str)
    assert isinstance(expected_model_manifest_id, str)
    assert isinstance(selected_case_authority, M6SQLiteCaseAuthorityDocument)
    assert isinstance(observed_model_calls, tuple)
    try:
        run_id = require_reference_token(expected_run_id, "M6 M3 model-document run_id")
        observations = tuple(
            M6UpgradeObservedModelCall.model_validate(
                value.model_dump(mode="json", exclude_computed_fields=True)
            )
            for value in observed_model_calls
            if type(value) is M6UpgradeObservedModelCall
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6SQLiteM3ModelDocumentFailureCode.INVALID_ARGUMENT)
    if len(observations) != len(observed_model_calls):
        _fail(M6SQLiteM3ModelDocumentFailureCode.INVALID_ARGUMENT)
    if len(observations) > MAX_M6_SQLITE_M3_MODEL_ROWS_PER_GROUP:
        _fail(M6SQLiteM3ModelDocumentFailureCode.ROW_LIMIT_EXCEEDED)
    if observations != observed_model_calls or observations != tuple(
        sorted(observations, key=lambda value: value.sort_key)
    ):
        _fail(M6SQLiteM3ModelDocumentFailureCode.INVALID_ARGUMENT)
    if len({value.request_id for value in observations}) != len(observations):
        _fail(M6SQLiteM3ModelDocumentFailureCode.INVALID_ARGUMENT)
    if any(
        value.layer != M6LockedModelCallLayer.SCREENING or value.role != M6LockedModelRole.SCREENING
        for value in observations
    ):
        _fail(M6SQLiteM3ModelDocumentFailureCode.INVALID_ARGUMENT)
    authority = selected_case_authority
    if not _case_authority_is_consistent(authority):
        _fail(M6SQLiteM3ModelDocumentFailureCode.CASE_BINDING_MISMATCH)
    if authority.case.run_id != run_id or authority.case.manifest_id != expected_manifest_id:
        _fail(M6SQLiteM3ModelDocumentFailureCode.SCOPE_MISMATCH)
    _active(connection)
    return (
        connection,
        run_id,
        expected_manifest_id,
        expected_model_manifest_id,
        authority,
        observations,
    )


def _physical_ref(
    *,
    kind: M6UpgradePhysicalArtifactKind,
    artifact_id: str,
    document_sha256: str,
    content_sha256: str,
    size_bytes: int,
) -> M6UpgradePhysicalArtifactRef:
    try:
        return M6UpgradePhysicalArtifactRef(
            source=_SOURCE,
            kind=kind,
            artifact_id=artifact_id,
            document_sha256=document_sha256,
            content_sha256=content_sha256,
            size_bytes=size_bytes,
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6SQLiteM3ModelDocumentFailureCode.PHYSICAL_PLAN_INVALID)


def _document_slot(
    connection: M6LiveReader,
    row: sqlite3.Row,
    *,
    route: M6SQLiteM3DocumentRoute,
    artifact_id: str,
    document_sha256: str,
    kind: M6UpgradePhysicalArtifactKind | None,
    content_sha256: str | None = None,
    physical_size_bytes: int | None = None,
) -> M6SQLiteM3DocumentSlot:
    canonical_bytes = document_bytes(connection, row, route)
    ref = None
    if kind is not None:
        ref = _physical_ref(
            kind=kind,
            artifact_id=artifact_id,
            document_sha256=document_sha256,
            content_sha256=(document_sha256 if content_sha256 is None else content_sha256),
            size_bytes=(canonical_bytes if physical_size_bytes is None else physical_size_bytes),
        )
    try:
        return M6SQLiteM3DocumentSlot(
            route=route,
            rowid=_integer(row, "document_rowid", minimum=1),
            artifact_id=artifact_id,
            document_sha256=document_sha256,
            document_bytes=canonical_bytes,
            index_identity_sha256=_row_identity(row, route.value),
            physical_ref=ref,
        )
    except (TypeError, ValueError):
        _fail(M6SQLiteM3ModelDocumentFailureCode.PHYSICAL_PLAN_INVALID)


@dataclass(frozen=True, slots=True)
class _Claim:
    row: sqlite3.Row
    observation: M6UpgradeObservedModelCall
    request_id: str
    request_sha256: str
    cache_key: str
    pack_key: tuple[str, int]
    purpose: str
    takeover_count: int
    request_slot: M6SQLiteM3DocumentSlot


@dataclass(frozen=True, slots=True)
class _Response:
    row: sqlite3.Row
    response_id: str
    request_id: str
    content_sha256: str
    response_slot: M6SQLiteM3DocumentSlot


@dataclass(frozen=True, slots=True)
class _Cache:
    row: sqlite3.Row
    request_id: str
    response_id: str
    output_schema_sha256: str
    request_slot: M6SQLiteM3DocumentSlot
    cache_slot: M6SQLiteM3DocumentSlot


@dataclass(frozen=True, slots=True)
class _Receipt:
    row: sqlite3.Row
    request_id: str
    response_id: str
    status: str
    parsed_output_id: str | None
    parsed_output_sha256: str | None
    repair_request_id: str | None
    slot: M6SQLiteM3DocumentSlot


@dataclass(frozen=True, slots=True)
class _Output:
    row: sqlite3.Row
    request_id: str
    response_id: str
    parsed_output_id: str
    parsed_output_sha256: str
    slot: M6SQLiteM3DocumentSlot


@dataclass(frozen=True, slots=True)
class _Failure:
    row: sqlite3.Row
    request_id: str
    authority_id: str
    claim_takeover_count: int
    slot: M6SQLiteM3DocumentSlot


@dataclass(frozen=True, slots=True)
class _Usage:
    row: sqlite3.Row
    request_id: str
    response_id: str
    case_revision: int
    consumer_kind: str
    consumer_id: str
    slot: M6SQLiteM3DocumentSlot


def _pack_key(row: sqlite3.Row) -> tuple[str, int]:
    return (
        _sha256(row, "evidence_pack_id"),
        _integer(row, "evidence_pack_version", minimum=1),
    )
