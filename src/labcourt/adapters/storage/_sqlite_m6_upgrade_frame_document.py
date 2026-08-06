"""Plan one M6 Frame physical reference from a caller-owned SQLite cut.

This adapter reads canonical Frame metadata only.  It deliberately does not
accept or invoke a pixel provider: the returned physical reference is a plan
whose LCPIX1 content digest still has to be proven by the fixed pixel verifier.
"""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass
from enum import StrEnum
from typing import NoReturn

from pydantic import ValidationError

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.m6_upgrade_physical import (
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactRef,
    M6UpgradePhysicalArtifactSource,
)
from labcourt.contracts.references import parse_frame_id, require_reference_token
from labcourt.exceptions import ContractViolation
from labcourt.ports.m6_perception import M6FrameAuthorityDocument
from labcourt.ports.pixels import LCPIX1_RGB8_HEADER_SIZE_BYTES

from ._sqlite_m6_live_read_cut import (
    M6LiveDocumentColumn,
    M6LiveReadCutError,
    M6LiveReader,
    M6SQLiteReadSession,
    is_m6_sqlite_read_session,
)

MAX_M6_SQLITE_FRAME_DOCUMENT_BYTES = 64 * 1024 * 1024
MAX_M6_SQLITE_FRAME_ROWS = 1
_SQLITE_OCTET_LENGTH_MIN_VERSION = (3, 43, 0)
_USE_SQLITE_OCTET_LENGTH = sqlite3.sqlite_version_info >= _SQLITE_OCTET_LENGTH_MIN_VERSION


class M6SQLiteFrameDocumentFailureCode(StrEnum):
    """Payload-free failures at the live Frame metadata boundary."""

    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    TRANSACTION_REQUIRED = "TRANSACTION_REQUIRED"
    SCOPE_NOT_FOUND = "SCOPE_NOT_FOUND"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"
    DOCUMENT_NOT_FOUND = "DOCUMENT_NOT_FOUND"
    ROW_LIMIT_EXCEEDED = "ROW_LIMIT_EXCEEDED"
    DOCUMENT_TOO_LARGE = "DOCUMENT_TOO_LARGE"
    DOCUMENT_INVALID = "DOCUMENT_INVALID"
    INDEX_BINDING_MISMATCH = "INDEX_BINDING_MISMATCH"
    PHYSICAL_PLAN_INVALID = "PHYSICAL_PLAN_INVALID"
    DATABASE_REJECTED = "DATABASE_REJECTED"


class M6SQLiteFrameDocumentError(ContractViolation):
    """A Frame plan could not be reconstructed from trusted storage."""

    def __init__(self, reason_code: M6SQLiteFrameDocumentFailureCode) -> None:
        if not isinstance(reason_code, M6SQLiteFrameDocumentFailureCode):
            raise TypeError("reason_code must be an M6 SQLite Frame document failure code")
        self.reason_code = reason_code
        super().__init__(f"M6 SQLite Frame document failed: {reason_code.value}")


@dataclass(frozen=True, slots=True)
class M6SQLiteFramePhysicalPlan:
    """Canonical Frame authority plus its not-yet-pixel-verified LCPIX1 ref."""

    frame_authority: M6FrameAuthorityDocument
    planned_artifact_ref: M6UpgradePhysicalArtifactRef

    def __post_init__(self) -> None:
        if not isinstance(self.frame_authority, M6FrameAuthorityDocument) or not isinstance(
            self.planned_artifact_ref,
            M6UpgradePhysicalArtifactRef,
        ):
            raise TypeError("M6 SQLite Frame plan requires typed authority and reference")
        ref = self.planned_artifact_ref
        authority = self.frame_authority
        if (
            ref.source != M6UpgradePhysicalArtifactSource.M2_PERCEPTION
            or ref.kind != M6UpgradePhysicalArtifactKind.FRAME
            or ref.artifact_id != authority.frame_id
            or ref.container_id is not None
            or ref.document_sha256 != authority.document_sha256
            or ref.content_sha256 != authority.content_sha256
        ):
            raise ValueError("M6 SQLite Frame plan is internally inconsistent")


def _fail(reason_code: M6SQLiteFrameDocumentFailureCode) -> NoReturn:
    raise M6SQLiteFrameDocumentError(reason_code)


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
    frame_id: object,
) -> tuple[M6SQLiteReadSession, str, str, str]:
    if (
        not is_m6_sqlite_read_session(connection)
        or not isinstance(expected_run_id, str)
        or not isinstance(frame_id, str)
    ):
        _fail(M6SQLiteFrameDocumentFailureCode.INVALID_ARGUMENT)
    try:
        run_id = require_reference_token(expected_run_id, "M6 Frame source run_id")
        parse_frame_id(frame_id)
    except (TypeError, ValueError):
        _fail(M6SQLiteFrameDocumentFailureCode.INVALID_ARGUMENT)
    if not _is_sha256(expected_manifest_id):
        _fail(M6SQLiteFrameDocumentFailureCode.INVALID_ARGUMENT)
    try:
        in_transaction = connection.in_transaction
    except (sqlite3.Error, M6LiveReadCutError):
        _fail(M6SQLiteFrameDocumentFailureCode.DATABASE_REJECTED)
    if not in_transaction:
        _fail(M6SQLiteFrameDocumentFailureCode.TRANSACTION_REQUIRED)
    assert isinstance(expected_manifest_id, str)
    return connection, run_id, expected_manifest_id, frame_id


def _rows(
    connection: M6SQLiteReadSession,
    sql: str,
    parameters: tuple[object, ...],
    *,
    limit: int,
) -> tuple[sqlite3.Row, ...]:
    if isinstance(connection, M6LiveReader):
        sealed_cursor = connection.execute(sql, parameters)
        try:
            return tuple(sealed_cursor.fetchmany(limit + 1))
        finally:
            sealed_cursor.close()
    cursor = connection.cursor()
    cursor.row_factory = sqlite3.Row
    try:
        cursor.execute(sql, parameters)
        return tuple(cursor.fetchmany(limit + 1))
    finally:
        cursor.close()


def _text(row: sqlite3.Row, column: str) -> str:
    value = row[column]
    if not isinstance(value, str):
        _fail(M6SQLiteFrameDocumentFailureCode.DOCUMENT_INVALID)
    return value


def _integer(row: sqlite3.Row, column: str) -> int:
    value = row[column]
    if not isinstance(value, int) or isinstance(value, bool):
        _fail(M6SQLiteFrameDocumentFailureCode.INDEX_BINDING_MISMATCH)
    return value


def _require_scope(
    connection: M6SQLiteReadSession,
    run_id: str,
    manifest_id: str,
) -> None:
    rows = _rows(
        connection,
        "SELECT manifest_id FROM runs WHERE run_id = ?",
        (run_id,),
        limit=MAX_M6_SQLITE_FRAME_ROWS,
    )
    if not rows:
        _fail(M6SQLiteFrameDocumentFailureCode.SCOPE_NOT_FOUND)
    if len(rows) != 1:
        _fail(M6SQLiteFrameDocumentFailureCode.ROW_LIMIT_EXCEEDED)
    if _text(rows[0], "manifest_id") != manifest_id:
        _fail(M6SQLiteFrameDocumentFailureCode.SCOPE_MISMATCH)


def _preflight_document(
    connection: M6SQLiteReadSession,
    run_id: str,
    manifest_id: str,
    frame_id: str,
) -> int:
    size_projection = (
        "octet_length(document_json) AS document_bytes"
        if _USE_SQLITE_OCTET_LENGTH
        else "NULL AS document_bytes"
    )
    rows = _rows(
        connection,
        f"""
        SELECT rowid AS frame_rowid, run_id, manifest_id,
               typeof(document_json) AS document_type,
               {size_projection}
        FROM frames
        WHERE run_id = ? AND frame_id = ?
        """,
        (run_id, frame_id),
        limit=MAX_M6_SQLITE_FRAME_ROWS,
    )
    if not rows:
        _fail(M6SQLiteFrameDocumentFailureCode.DOCUMENT_NOT_FOUND)
    if len(rows) != 1:
        _fail(M6SQLiteFrameDocumentFailureCode.ROW_LIMIT_EXCEEDED)
    row = rows[0]
    if _text(row, "run_id") != run_id or _text(row, "manifest_id") != manifest_id:
        _fail(M6SQLiteFrameDocumentFailureCode.SCOPE_MISMATCH)
    if _text(row, "document_type") != "text":
        _fail(M6SQLiteFrameDocumentFailureCode.DOCUMENT_INVALID)
    document_bytes = row["document_bytes"]
    if not _USE_SQLITE_OCTET_LENGTH:
        frame_rowid = row["frame_rowid"]
        if not isinstance(frame_rowid, int) or isinstance(frame_rowid, bool) or frame_rowid <= 0:
            _fail(M6SQLiteFrameDocumentFailureCode.DATABASE_REJECTED)
        if isinstance(connection, M6LiveReader):
            document_bytes = connection.document_octet_length(
                M6LiveDocumentColumn.FRAME_DOCUMENT,
                frame_rowid,
            )
        else:
            blob = connection.blobopen(
                "frames",
                "document_json",
                frame_rowid,
                readonly=True,
            )
            try:
                document_bytes = len(blob)
            finally:
                blob.close()
    if (
        not isinstance(document_bytes, int)
        or isinstance(document_bytes, bool)
        or document_bytes <= 0
    ):
        _fail(M6SQLiteFrameDocumentFailureCode.DOCUMENT_INVALID)
    if document_bytes > MAX_M6_SQLITE_FRAME_DOCUMENT_BYTES:
        _fail(M6SQLiteFrameDocumentFailureCode.DOCUMENT_TOO_LARGE)
    return document_bytes


def _read_frame_row(
    connection: M6SQLiteReadSession,
    run_id: str,
    frame_id: str,
) -> sqlite3.Row:
    rows = _rows(
        connection,
        """
        SELECT run_id, frame_id, manifest_id, camera_id, stream_id,
               frame_index, fps_num, fps_den, width, height,
               content_sha256, document_json, document_sha256
        FROM frames
        WHERE run_id = ? AND frame_id = ?
        """,
        (run_id, frame_id),
        limit=MAX_M6_SQLITE_FRAME_ROWS,
    )
    if not rows:
        _fail(M6SQLiteFrameDocumentFailureCode.DOCUMENT_NOT_FOUND)
    if len(rows) != 1:
        _fail(M6SQLiteFrameDocumentFailureCode.ROW_LIMIT_EXCEEDED)
    return rows[0]


def _decode_frame(row: sqlite3.Row, canonical_document: str) -> FrameRef:
    try:
        frame = FrameRef.model_validate_json(canonical_document)
    except (TypeError, ValueError, ValidationError, UnicodeError):
        _fail(M6SQLiteFrameDocumentFailureCode.DOCUMENT_INVALID)
    if (
        frame.content_sha256 is None
        or canonical_json(frame.model_dump(mode="json")) != canonical_document
    ):
        _fail(M6SQLiteFrameDocumentFailureCode.DOCUMENT_INVALID)
    indexed = (
        _text(row, "frame_id"),
        _text(row, "camera_id"),
        _text(row, "stream_id"),
        _integer(row, "frame_index"),
        _integer(row, "fps_num"),
        _integer(row, "fps_den"),
        _integer(row, "width"),
        _integer(row, "height"),
        _text(row, "content_sha256"),
    )
    derived = (
        frame.frame_id,
        frame.camera_id,
        frame.stream_id,
        frame.frame_index,
        frame.fps_num,
        frame.fps_den,
        frame.width,
        frame.height,
        frame.content_sha256,
    )
    if indexed != derived:
        _fail(M6SQLiteFrameDocumentFailureCode.INDEX_BINDING_MISMATCH)
    return frame


def plan_m6_sqlite_frame_physical_identity(
    *,
    connection: M6SQLiteReadSession,
    expected_run_id: str,
    expected_manifest_id: str,
    frame_id: str,
) -> M6SQLiteFramePhysicalPlan:
    """Read one exact Frame document and plan its LCPIX1 physical identity.

    The caller must own an open transaction.  Canonical byte size is checked
    before the document text is fetched and decoded.  Pixel bytes are neither
    accepted nor read here.
    """

    controlled, run_id, manifest_id, controlled_frame_id = _validated_arguments(
        connection,
        expected_run_id,
        expected_manifest_id,
        frame_id,
    )
    try:
        _require_scope(controlled, run_id, manifest_id)
        preflight_bytes = _preflight_document(
            controlled,
            run_id,
            manifest_id,
            controlled_frame_id,
        )
        row = _read_frame_row(controlled, run_id, controlled_frame_id)
        if _text(row, "run_id") != run_id or _text(row, "manifest_id") != manifest_id:
            _fail(M6SQLiteFrameDocumentFailureCode.SCOPE_MISMATCH)
        canonical_document = _text(row, "document_json")
        actual_bytes = len(canonical_document.encode("utf-8"))
        if actual_bytes != preflight_bytes:
            _fail(M6SQLiteFrameDocumentFailureCode.DATABASE_REJECTED)
        if actual_bytes > MAX_M6_SQLITE_FRAME_DOCUMENT_BYTES:
            _fail(M6SQLiteFrameDocumentFailureCode.DOCUMENT_TOO_LARGE)
        frame = _decode_frame(row, canonical_document)
        content_sha256 = frame.content_sha256
        if content_sha256 is None:
            _fail(M6SQLiteFrameDocumentFailureCode.DOCUMENT_INVALID)
        document_sha256 = hashlib.sha256(canonical_document.encode("utf-8")).hexdigest()
        if _text(row, "document_sha256") != document_sha256:
            _fail(M6SQLiteFrameDocumentFailureCode.INDEX_BINDING_MISMATCH)
        authority = M6FrameAuthorityDocument(
            run_id=run_id,
            manifest_id=manifest_id,
            frame_id=frame.frame_id,
            content_sha256=content_sha256,
            canonical_document=canonical_document,
            document_sha256=document_sha256,
        )
        planned_ref = M6UpgradePhysicalArtifactRef(
            source=M6UpgradePhysicalArtifactSource.M2_PERCEPTION,
            kind=M6UpgradePhysicalArtifactKind.FRAME,
            artifact_id=frame.frame_id,
            document_sha256=document_sha256,
            content_sha256=content_sha256,
            size_bytes=(LCPIX1_RGB8_HEADER_SIZE_BYTES + frame.width * frame.height * 3),
        )
        return M6SQLiteFramePhysicalPlan(
            frame_authority=authority,
            planned_artifact_ref=planned_ref,
        )
    except M6SQLiteFrameDocumentError:
        raise
    except (sqlite3.Error, M6LiveReadCutError):
        _fail(M6SQLiteFrameDocumentFailureCode.DATABASE_REJECTED)
    except (KeyError, IndexError):
        _fail(M6SQLiteFrameDocumentFailureCode.DATABASE_REJECTED)
    except (TypeError, ValueError, ValidationError):
        _fail(M6SQLiteFrameDocumentFailureCode.PHYSICAL_PLAN_INVALID)


__all__ = [
    "MAX_M6_SQLITE_FRAME_DOCUMENT_BYTES",
    "MAX_M6_SQLITE_FRAME_ROWS",
    "M6SQLiteFrameDocumentError",
    "M6SQLiteFrameDocumentFailureCode",
    "M6SQLiteFramePhysicalPlan",
    "plan_m6_sqlite_frame_physical_identity",
]
