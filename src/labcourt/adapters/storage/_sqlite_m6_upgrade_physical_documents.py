"""Bounded canonical SQLite lookups for M6 physical artifact verification.

The caller owns the transaction.  Requiring an already-open transaction keeps
the byte preflight, typed decode, duplicated-index checks, and reconstructed
physical reference inside one SQLite snapshot.  Routes that need raw bytes,
derived documents, or model-closure validation are deliberately unsupported.
"""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, NoReturn, cast

from pydantic import BaseModel, ValidationError

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.detections import Detection
from labcourt.contracts.m4_projection import M4ProjectionArtifactKind
from labcourt.contracts.m5_projection import M5AuthorityKind
from labcourt.contracts.m6_upgrade_physical import (
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactRef,
    M6UpgradePhysicalArtifactSource,
    M6UpgradePhysicalByteAuthority,
    m6_upgrade_physical_byte_authority_for,
)
from labcourt.contracts.references import parse_frame_id, require_reference_token
from labcourt.exceptions import ContractViolation

from ._readonly_m4_artifact_codec import (
    M4_TYPED_TABLES,
    M4DocumentFailure,
    M4IndexFailure,
    M4TableSpec,
    load_m4_record,
)
from ._readonly_m5_artifact_codec import (
    M5_TABLE_SPECS,
    M5DocumentFailure,
    M5IndexFailure,
    M5TableSpec,
    load_m5_record,
)
from ._sqlite_m6_live_read_cut import (
    M6LiveDocumentColumn,
    M6LiveReadCutError,
    M6LiveReader,
    M6SQLiteReadSession,
    is_m6_sqlite_read_session,
)

MAX_M6_SQLITE_CANONICAL_PHYSICAL_DOCUMENT_BYTES = 64 * 1024 * 1024
MAX_M6_SQLITE_CANONICAL_PHYSICAL_ROWS = 1
_SQLITE_OCTET_LENGTH_MIN_VERSION = (3, 43, 0)
_USE_SQLITE_OCTET_LENGTH = sqlite3.sqlite_version_info >= _SQLITE_OCTET_LENGTH_MIN_VERSION


class M6SQLitePhysicalDocumentFailureCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    TRANSACTION_REQUIRED = "TRANSACTION_REQUIRED"
    UNSUPPORTED = "UNSUPPORTED"
    SCOPE_NOT_FOUND = "SCOPE_NOT_FOUND"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"
    DOCUMENT_NOT_FOUND = "DOCUMENT_NOT_FOUND"
    ROW_LIMIT_EXCEEDED = "ROW_LIMIT_EXCEEDED"
    DOCUMENT_TOO_LARGE = "DOCUMENT_TOO_LARGE"
    DOCUMENT_INVALID = "DOCUMENT_INVALID"
    INDEX_BINDING_MISMATCH = "INDEX_BINDING_MISMATCH"
    CLAIM_MISMATCH = "CLAIM_MISMATCH"
    DATABASE_REJECTED = "DATABASE_REJECTED"


class M6SQLitePhysicalDocumentError(ContractViolation):
    """Typed, payload-free failure at the canonical physical lookup boundary."""

    def __init__(self, reason_code: M6SQLitePhysicalDocumentFailureCode) -> None:
        if not isinstance(reason_code, M6SQLitePhysicalDocumentFailureCode):
            raise TypeError("reason_code must be an M6 SQLite physical document failure code")
        self.reason_code = reason_code
        super().__init__(f"M6 SQLite physical document failed: {reason_code.value}")


class M6SQLitePhysicalRouteCapability(StrEnum):
    SUPPORTED_CANONICAL = "SUPPORTED_CANONICAL"
    SUPPORTED_SELECTED_CASE_PLAN = "SUPPORTED_SELECTED_CASE_PLAN"
    UNSUPPORTED_MODEL_CLOSURE = "UNSUPPORTED_MODEL_CLOSURE"
    UNSUPPORTED_PHYSICAL_BYTES = "UNSUPPORTED_PHYSICAL_BYTES"


class _Decoder(StrEnum):
    DETECTION = "DETECTION"
    M4_TOOL_EXECUTION_MANIFEST = "M4_TOOL_EXECUTION_MANIFEST"
    M5_EMBEDDING = "M5_EMBEDDING"
    M5_PRECEDENT_EXPOSURE = "M5_PRECEDENT_EXPOSURE"


@dataclass(frozen=True, slots=True)
class _Route:
    capability: M6SQLitePhysicalRouteCapability
    table_name: str | None = None
    identity_column: str | None = None
    read_sql: str | None = None
    json_column: str | None = None
    decoder: _Decoder | None = None

    def __post_init__(self) -> None:
        fields = (
            self.table_name,
            self.identity_column,
            self.read_sql,
            self.json_column,
            self.decoder,
        )
        if self.capability == M6SQLitePhysicalRouteCapability.SUPPORTED_CANONICAL:
            if any(value is None for value in fields):
                raise RuntimeError("supported M6 SQLite physical route is incomplete")
        elif any(value is not None for value in fields):
            raise RuntimeError("unsupported M6 SQLite physical route contains SQL")


@dataclass(frozen=True, slots=True)
class M6SQLiteCanonicalPhysicalDocument:
    """One typed canonical document and its independently reconstructed ref."""

    artifact_ref: M6UpgradePhysicalArtifactRef
    document: BaseModel
    canonical_document: str

    def __post_init__(self) -> None:
        if not isinstance(self.artifact_ref, M6UpgradePhysicalArtifactRef) or not isinstance(
            self.document, BaseModel
        ):
            raise TypeError("M6 canonical physical document requires typed content")
        if canonical_json(self.document.model_dump(mode="json")) != self.canonical_document:
            raise ValueError("M6 canonical physical document is not canonical")


_SUPPORTED = M6SQLitePhysicalRouteCapability.SUPPORTED_CANONICAL
_MODEL_DEFERRED = M6SQLitePhysicalRouteCapability.UNSUPPORTED_MODEL_CLOSURE
_PHYSICAL_UNSUPPORTED = M6SQLitePhysicalRouteCapability.UNSUPPORTED_PHYSICAL_BYTES

_DETECTION_ROUTE = _Route(
    capability=_SUPPORTED,
    table_name="detections",
    identity_column="detection_id",
    read_sql="""
        SELECT run_id, detection_id, frame_id, manifest_id,
               detector_manifest_id, label, document_json, document_sha256
        FROM detections
        WHERE run_id = ? AND detection_id = ?
    """,
    json_column="document_json",
    decoder=_Decoder.DETECTION,
)
_SELECTED_CASE_PLAN = M6SQLitePhysicalRouteCapability.SUPPORTED_SELECTED_CASE_PLAN
_EVIDENCE_PACK_ROUTE = _Route(capability=_SELECTED_CASE_PLAN)
_M4_TOOL_MANIFEST_ROUTE = _Route(
    capability=_SUPPORTED,
    table_name="m4_tool_execution_manifests",
    identity_column="execution_manifest_id",
    read_sql="""
        SELECT *
        FROM m4_tool_execution_manifests
        WHERE run_id = ? AND execution_manifest_id = ?
    """,
    json_column="manifest_json",
    decoder=_Decoder.M4_TOOL_EXECUTION_MANIFEST,
)
_M5_EMBEDDING_ROUTE = _Route(
    capability=_SUPPORTED,
    table_name="precedent_embeddings",
    identity_column="embedding_id",
    read_sql="""
        SELECT *
        FROM precedent_embeddings
        WHERE run_id = ? AND embedding_id = ?
    """,
    json_column="embedding_json",
    decoder=_Decoder.M5_EMBEDDING,
)
_M5_EXPOSURE_ROUTE = _Route(
    capability=_SUPPORTED,
    table_name="m5_precedent_exposures",
    identity_column="exposure_id",
    read_sql="""
        SELECT *
        FROM m5_precedent_exposures
        WHERE run_id = ? AND exposure_id = ?
    """,
    json_column="exposure_json",
    decoder=_Decoder.M5_PRECEDENT_EXPOSURE,
)

# This explicit matrix is intentionally not inferred from table names or caller
# input.  Every legal contract route is either pinned to literal SQL or pinned
# to one fail-closed unsupported capability.
_ROUTES: dict[
    tuple[M6UpgradePhysicalArtifactSource, M6UpgradePhysicalArtifactKind],
    _Route,
] = {
    (
        M6UpgradePhysicalArtifactSource.M2_PERCEPTION,
        M6UpgradePhysicalArtifactKind.FRAME,
    ): _Route(_PHYSICAL_UNSUPPORTED),
    (
        M6UpgradePhysicalArtifactSource.M2_PERCEPTION,
        M6UpgradePhysicalArtifactKind.DETECTION,
    ): _DETECTION_ROUTE,
    (
        M6UpgradePhysicalArtifactSource.M2_EVIDENCE,
        M6UpgradePhysicalArtifactKind.EVIDENCE_PACK,
    ): _EVIDENCE_PACK_ROUTE,
    (
        M6UpgradePhysicalArtifactSource.M3_SCREENING_MODEL,
        M6UpgradePhysicalArtifactKind.MODEL_REQUEST,
    ): _Route(_MODEL_DEFERRED),
    (
        M6UpgradePhysicalArtifactSource.M3_SCREENING_MODEL,
        M6UpgradePhysicalArtifactKind.MODEL_RESPONSE,
    ): _Route(_PHYSICAL_UNSUPPORTED),
    (
        M6UpgradePhysicalArtifactSource.M3_SCREENING_MODEL,
        M6UpgradePhysicalArtifactKind.MODEL_CACHE,
    ): _Route(_MODEL_DEFERRED),
    (
        M6UpgradePhysicalArtifactSource.M3_SCREENING_MODEL,
        M6UpgradePhysicalArtifactKind.MODEL_PARSE_RECEIPT,
    ): _Route(_MODEL_DEFERRED),
    (
        M6UpgradePhysicalArtifactSource.M3_SCREENING_MODEL,
        M6UpgradePhysicalArtifactKind.MODEL_PARSED_OUTPUT,
    ): _Route(_MODEL_DEFERRED),
    (
        M6UpgradePhysicalArtifactSource.M3_SCREENING_MODEL,
        M6UpgradePhysicalArtifactKind.MODEL_CALL_FAILURE,
    ): _Route(_MODEL_DEFERRED),
    (
        M6UpgradePhysicalArtifactSource.M3_SCREENING_MODEL,
        M6UpgradePhysicalArtifactKind.MODEL_USAGE_RECEIPT,
    ): _Route(_MODEL_DEFERRED),
    (
        M6UpgradePhysicalArtifactSource.M4_HEARING_MODEL,
        M6UpgradePhysicalArtifactKind.MODEL_REQUEST,
    ): _Route(_MODEL_DEFERRED),
    (
        M6UpgradePhysicalArtifactSource.M4_HEARING_MODEL,
        M6UpgradePhysicalArtifactKind.MODEL_RESPONSE,
    ): _Route(_PHYSICAL_UNSUPPORTED),
    (
        M6UpgradePhysicalArtifactSource.M4_HEARING_MODEL,
        M6UpgradePhysicalArtifactKind.MODEL_CACHE,
    ): _Route(_MODEL_DEFERRED),
    (
        M6UpgradePhysicalArtifactSource.M4_HEARING_MODEL,
        M6UpgradePhysicalArtifactKind.MODEL_PARSE_RECEIPT,
    ): _Route(_MODEL_DEFERRED),
    (
        M6UpgradePhysicalArtifactSource.M4_HEARING_MODEL,
        M6UpgradePhysicalArtifactKind.MODEL_PARSED_OUTPUT,
    ): _Route(_MODEL_DEFERRED),
    (
        M6UpgradePhysicalArtifactSource.M4_HEARING_MODEL,
        M6UpgradePhysicalArtifactKind.MODEL_CALL_FAILURE,
    ): _Route(_MODEL_DEFERRED),
    (
        M6UpgradePhysicalArtifactSource.M4_HEARING_MODEL,
        M6UpgradePhysicalArtifactKind.MODEL_USAGE_RECEIPT,
    ): _Route(_MODEL_DEFERRED),
    (
        M6UpgradePhysicalArtifactSource.M4_ACQUISITION,
        M6UpgradePhysicalArtifactKind.TOOL_EXECUTION_MANIFEST,
    ): _M4_TOOL_MANIFEST_ROUTE,
    (
        M6UpgradePhysicalArtifactSource.M4_ACQUISITION,
        M6UpgradePhysicalArtifactKind.TOOL_RESULT,
    ): _Route(_PHYSICAL_UNSUPPORTED),
    (
        M6UpgradePhysicalArtifactSource.M5_PRECEDENT,
        M6UpgradePhysicalArtifactKind.EMBEDDING,
    ): _M5_EMBEDDING_ROUTE,
    (
        M6UpgradePhysicalArtifactSource.M5_PRECEDENT,
        M6UpgradePhysicalArtifactKind.PRECEDENT_EXPOSURE,
    ): _M5_EXPOSURE_ROUTE,
}


def _legal_routes() -> frozenset[
    tuple[M6UpgradePhysicalArtifactSource, M6UpgradePhysicalArtifactKind]
]:
    legal: set[tuple[M6UpgradePhysicalArtifactSource, M6UpgradePhysicalArtifactKind]] = set()
    for source in M6UpgradePhysicalArtifactSource:
        for kind in M6UpgradePhysicalArtifactKind:
            try:
                m6_upgrade_physical_byte_authority_for(source, kind)
            except ValueError:
                continue
            legal.add((source, kind))
    return frozenset(legal)


if frozenset(_ROUTES) != _legal_routes():
    raise RuntimeError("M6 SQLite physical routes must exhaust the legal contract matrix")
if any(
    m6_upgrade_physical_byte_authority_for(source, kind)
    != M6UpgradePhysicalByteAuthority.CANONICAL_JSON
    for (source, kind), route in _ROUTES.items()
    if route.capability == _SUPPORTED
):
    raise RuntimeError("M6 SQLite canonical route has a non-canonical byte authority")

_M4_TOOL_SPEC = next(
    (
        spec
        for spec in M4_TYPED_TABLES
        if spec.kind == M4ProjectionArtifactKind.TOOL_EXECUTION_MANIFEST
        and spec.table == "m4_tool_execution_manifests"
    ),
    None,
)
_M5_EMBEDDING_SPEC = next(
    (
        spec
        for spec in M5_TABLE_SPECS
        if spec.kind == M5AuthorityKind.PRECEDENT_EMBEDDING and spec.table == "precedent_embeddings"
    ),
    None,
)
_M5_EXPOSURE_SPEC = next(
    (
        spec
        for spec in M5_TABLE_SPECS
        if spec.kind == M5AuthorityKind.PRECEDENT_EXPOSURE
        and spec.table == "m5_precedent_exposures"
    ),
    None,
)
if (
    not isinstance(_M4_TOOL_SPEC, M4TableSpec)
    or not isinstance(_M5_EMBEDDING_SPEC, M5TableSpec)
    or not isinstance(_M5_EXPOSURE_SPEC, M5TableSpec)
):
    raise RuntimeError("M6 canonical physical routes lost their strict row codec")


def _fail(reason_code: M6SQLitePhysicalDocumentFailureCode) -> NoReturn:
    raise M6SQLitePhysicalDocumentError(reason_code)


def m6_sqlite_physical_route_capability(
    source: M6UpgradePhysicalArtifactSource,
    kind: M6UpgradePhysicalArtifactKind,
) -> M6SQLitePhysicalRouteCapability:
    """Return the pinned SQLite capability for one legal physical route."""

    if not isinstance(source, M6UpgradePhysicalArtifactSource) or not isinstance(
        kind, M6UpgradePhysicalArtifactKind
    ):
        raise TypeError("M6 SQLite physical route requires typed source and kind")
    route = _ROUTES.get((source, kind))
    if route is None:
        raise ValueError("M6 SQLite physical route is not legal")
    return route.capability


def _validated_identity_inputs(
    connection: object,
    source: object,
    kind: object,
    artifact_id: object,
    expected_run_id: object,
    expected_manifest_id: object,
) -> tuple[
    M6SQLiteReadSession,
    M6UpgradePhysicalArtifactSource,
    M6UpgradePhysicalArtifactKind,
    str,
    str,
    str,
    _Route,
]:
    if (
        not is_m6_sqlite_read_session(connection)
        or not isinstance(source, M6UpgradePhysicalArtifactSource)
        or not isinstance(kind, M6UpgradePhysicalArtifactKind)
        or not isinstance(artifact_id, str)
        or not isinstance(expected_run_id, str)
    ):
        _fail(M6SQLitePhysicalDocumentFailureCode.INVALID_ARGUMENT)
    try:
        if kind == M6UpgradePhysicalArtifactKind.FRAME:
            parse_frame_id(artifact_id)
            controlled_artifact_id = artifact_id
        else:
            controlled_artifact_id = require_reference_token(
                artifact_id,
                "M6 canonical physical artifact_id",
            )
        controlled_run_id = require_reference_token(
            expected_run_id,
            "M6 canonical physical source run_id",
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6SQLitePhysicalDocumentFailureCode.INVALID_ARGUMENT)
    if (
        not isinstance(expected_manifest_id, str)
        or len(expected_manifest_id) != 64
        or any(character not in "0123456789abcdef" for character in expected_manifest_id)
    ):
        _fail(M6SQLitePhysicalDocumentFailureCode.INVALID_ARGUMENT)
    route = _ROUTES.get((source, kind))
    if route is None:
        _fail(M6SQLitePhysicalDocumentFailureCode.INVALID_ARGUMENT)
    if route.capability != _SUPPORTED:
        _fail(M6SQLitePhysicalDocumentFailureCode.UNSUPPORTED)
    try:
        in_transaction = connection.in_transaction
    except (sqlite3.Error, M6LiveReadCutError):
        _fail(M6SQLitePhysicalDocumentFailureCode.DATABASE_REJECTED)
    if not in_transaction:
        _fail(M6SQLitePhysicalDocumentFailureCode.TRANSACTION_REQUIRED)
    return (
        connection,
        source,
        kind,
        controlled_artifact_id,
        controlled_run_id,
        expected_manifest_id,
        route,
    )


def _validated_claim(claim: object) -> M6UpgradePhysicalArtifactRef:
    if not isinstance(claim, M6UpgradePhysicalArtifactRef):
        _fail(M6SQLitePhysicalDocumentFailureCode.INVALID_ARGUMENT)
    try:
        controlled = M6UpgradePhysicalArtifactRef.model_validate(
            claim.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6SQLitePhysicalDocumentFailureCode.INVALID_ARGUMENT)
    if controlled != claim:
        _fail(M6SQLitePhysicalDocumentFailureCode.INVALID_ARGUMENT)
    return controlled


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


def _require_run_scope(
    connection: M6SQLiteReadSession,
    run_id: str,
    manifest_id: str,
) -> None:
    rows = _rows(
        connection,
        "SELECT manifest_id FROM runs WHERE run_id = ?",
        (run_id,),
        limit=MAX_M6_SQLITE_CANONICAL_PHYSICAL_ROWS,
    )
    if not rows:
        _fail(M6SQLitePhysicalDocumentFailureCode.SCOPE_NOT_FOUND)
    if len(rows) != 1:
        _fail(M6SQLitePhysicalDocumentFailureCode.ROW_LIMIT_EXCEEDED)
    observed = rows[0]["manifest_id"]
    if not isinstance(observed, str) or observed != manifest_id:
        _fail(M6SQLitePhysicalDocumentFailureCode.SCOPE_MISMATCH)


def _preflight_document(
    connection: M6SQLiteReadSession,
    route: _Route,
    run_id: str,
    artifact_id: str,
) -> int:
    assert route.table_name is not None
    assert route.identity_column is not None
    assert route.json_column is not None
    size_projection = (
        f"octet_length({route.json_column}) AS document_bytes"
        if _USE_SQLITE_OCTET_LENGTH
        else "NULL AS document_bytes"
    )
    rows = _rows(
        connection,
        f"""
        SELECT rowid AS document_rowid,
               typeof({route.json_column}) AS document_type,
               {size_projection}
        FROM {route.table_name}
        WHERE run_id = ? AND {route.identity_column} = ?
        """,
        (run_id, artifact_id),
        limit=MAX_M6_SQLITE_CANONICAL_PHYSICAL_ROWS,
    )
    if not rows:
        _fail(M6SQLitePhysicalDocumentFailureCode.DOCUMENT_NOT_FOUND)
    if len(rows) > MAX_M6_SQLITE_CANONICAL_PHYSICAL_ROWS:
        _fail(M6SQLitePhysicalDocumentFailureCode.ROW_LIMIT_EXCEEDED)
    row = rows[0]
    if _text(row, "document_type") != "text":
        _fail(M6SQLitePhysicalDocumentFailureCode.DOCUMENT_INVALID)
    document_bytes = row["document_bytes"]
    if not _USE_SQLITE_OCTET_LENGTH:
        document_rowid = row["document_rowid"]
        if (
            not isinstance(document_rowid, int)
            or isinstance(document_rowid, bool)
            or document_rowid <= 0
        ):
            _fail(M6SQLitePhysicalDocumentFailureCode.DATABASE_REJECTED)
        if isinstance(connection, M6LiveReader):
            if (route.table_name, route.json_column) != (
                "detections",
                "document_json",
            ):
                _fail(M6SQLitePhysicalDocumentFailureCode.DATABASE_REJECTED)
            document_bytes = connection.document_octet_length(
                M6LiveDocumentColumn.DETECTION_DOCUMENT,
                document_rowid,
            )
        else:
            blob = connection.blobopen(
                route.table_name,
                route.json_column,
                document_rowid,
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
        _fail(M6SQLitePhysicalDocumentFailureCode.DOCUMENT_INVALID)
    if document_bytes > MAX_M6_SQLITE_CANONICAL_PHYSICAL_DOCUMENT_BYTES:
        _fail(M6SQLitePhysicalDocumentFailureCode.DOCUMENT_TOO_LARGE)
    return document_bytes


def _read_one(
    connection: M6SQLiteReadSession,
    route: _Route,
    run_id: str,
    artifact_id: str,
) -> sqlite3.Row:
    assert route.read_sql is not None
    rows = _rows(
        connection,
        route.read_sql,
        (run_id, artifact_id),
        limit=MAX_M6_SQLITE_CANONICAL_PHYSICAL_ROWS,
    )
    if not rows:
        _fail(M6SQLitePhysicalDocumentFailureCode.DOCUMENT_NOT_FOUND)
    if len(rows) != 1:
        _fail(M6SQLitePhysicalDocumentFailureCode.ROW_LIMIT_EXCEEDED)
    return rows[0]


def _text(row: sqlite3.Row, column: str) -> str:
    value = row[column]
    if not isinstance(value, str):
        _fail(M6SQLitePhysicalDocumentFailureCode.DOCUMENT_INVALID)
    return value


def _integer(row: sqlite3.Row, column: str) -> int:
    value = row[column]
    if not isinstance(value, int) or isinstance(value, bool):
        _fail(M6SQLitePhysicalDocumentFailureCode.INDEX_BINDING_MISMATCH)
    return value


def _require_row_scope(row: sqlite3.Row, run_id: str, manifest_id: str) -> None:
    if _text(row, "run_id") != run_id or _text(row, "manifest_id") != manifest_id:
        _fail(M6SQLitePhysicalDocumentFailureCode.SCOPE_MISMATCH)


def _decode_detection(row: sqlite3.Row, raw: str) -> Detection:
    try:
        detection = Detection.model_validate_json(raw)
    except (TypeError, ValueError, ValidationError, UnicodeError):
        _fail(M6SQLitePhysicalDocumentFailureCode.DOCUMENT_INVALID)
    if canonical_json(detection.model_dump(mode="json")) != raw:
        _fail(M6SQLitePhysicalDocumentFailureCode.DOCUMENT_INVALID)
    if (
        _text(row, "detection_id") != detection.detection_id
        or _text(row, "frame_id") != detection.frame_id
        or _text(row, "detector_manifest_id") != detection.model_manifest_id
        or _text(row, "label") != detection.label
    ):
        _fail(M6SQLitePhysicalDocumentFailureCode.INDEX_BINDING_MISMATCH)
    return detection


def _decode_document(
    route: _Route,
    row: sqlite3.Row,
    raw: str,
    manifest_id: str,
) -> BaseModel:
    decoder = route.decoder
    if decoder == _Decoder.DETECTION:
        return _decode_detection(row, raw)
    try:
        if decoder == _Decoder.M4_TOOL_EXECUTION_MANIFEST:
            m4_record = load_m4_record(row, cast(M4TableSpec[Any], _M4_TOOL_SPEC))
            if not isinstance(m4_record.document, BaseModel) or (
                m4_record.canonical_document != raw
            ):
                _fail(M6SQLitePhysicalDocumentFailureCode.DOCUMENT_INVALID)
            return m4_record.document
        elif decoder == _Decoder.M5_EMBEDDING:
            m5_record = load_m5_record(
                row,
                cast(M5TableSpec, _M5_EMBEDDING_SPEC),
                manifest_id,
            )
        elif decoder == _Decoder.M5_PRECEDENT_EXPOSURE:
            m5_record = load_m5_record(
                row,
                cast(M5TableSpec, _M5_EXPOSURE_SPEC),
                manifest_id,
            )
        else:
            _fail(M6SQLitePhysicalDocumentFailureCode.DATABASE_REJECTED)
    except (M4DocumentFailure, M5DocumentFailure):
        _fail(M6SQLitePhysicalDocumentFailureCode.DOCUMENT_INVALID)
    except (M4IndexFailure, M5IndexFailure):
        _fail(M6SQLitePhysicalDocumentFailureCode.INDEX_BINDING_MISMATCH)
    if not isinstance(m5_record.document, BaseModel) or m5_record.canonical_document != raw:
        _fail(M6SQLitePhysicalDocumentFailureCode.DOCUMENT_INVALID)
    return m5_record.document


def resolve_m6_sqlite_canonical_physical_identity(
    *,
    connection: M6SQLiteReadSession,
    source: M6UpgradePhysicalArtifactSource,
    kind: M6UpgradePhysicalArtifactKind,
    artifact_id: str,
    expected_run_id: str,
    expected_manifest_id: str,
) -> M6SQLiteCanonicalPhysicalDocument:
    """Rebuild one canonical physical ref from storage-selected identity.

    No digest, byte count, or container claim is accepted. This makes the
    function suitable for an independently enumerated exact-set authority;
    the claim-checking wrapper below remains available at persistence edges.
    """

    (
        controlled_connection,
        controlled_source,
        controlled_kind,
        controlled_artifact_id,
        run_id,
        manifest_id,
        route,
    ) = _validated_identity_inputs(
        connection,
        source,
        kind,
        artifact_id,
        expected_run_id,
        expected_manifest_id,
    )
    try:
        _require_run_scope(controlled_connection, run_id, manifest_id)
        preflight_bytes = _preflight_document(
            controlled_connection,
            route,
            run_id,
            controlled_artifact_id,
        )
        row = _read_one(
            controlled_connection,
            route,
            run_id,
            controlled_artifact_id,
        )
        _require_row_scope(row, run_id, manifest_id)
        assert route.json_column is not None
        raw = _text(row, route.json_column)
        actual_bytes = len(raw.encode("utf-8"))
        if actual_bytes != preflight_bytes:
            _fail(M6SQLitePhysicalDocumentFailureCode.DATABASE_REJECTED)
        if actual_bytes > MAX_M6_SQLITE_CANONICAL_PHYSICAL_DOCUMENT_BYTES:
            _fail(M6SQLitePhysicalDocumentFailureCode.DOCUMENT_TOO_LARGE)
        document = _decode_document(route, row, raw, manifest_id)
        document_sha256 = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        if _text(row, "document_sha256") != document_sha256:
            _fail(M6SQLitePhysicalDocumentFailureCode.INDEX_BINDING_MISMATCH)
        container_id = document.frame_id if isinstance(document, Detection) else None
        reconstructed = M6UpgradePhysicalArtifactRef(
            source=controlled_source,
            kind=controlled_kind,
            artifact_id=controlled_artifact_id,
            container_id=container_id,
            document_sha256=document_sha256,
            content_sha256=document_sha256,
            size_bytes=actual_bytes,
        )
        return M6SQLiteCanonicalPhysicalDocument(
            artifact_ref=reconstructed,
            document=document,
            canonical_document=raw,
        )
    except M6SQLitePhysicalDocumentError:
        raise
    except (sqlite3.Error, M6LiveReadCutError):
        _fail(M6SQLitePhysicalDocumentFailureCode.DATABASE_REJECTED)
    except (KeyError, IndexError):
        _fail(M6SQLitePhysicalDocumentFailureCode.DATABASE_REJECTED)


def resolve_m6_sqlite_canonical_physical_document(
    *,
    connection: M6SQLiteReadSession,
    claim: M6UpgradePhysicalArtifactRef,
    expected_run_id: str,
    expected_manifest_id: str,
) -> M6SQLiteCanonicalPhysicalDocument:
    """Resolve storage bytes, then require equality with one untrusted claim."""

    controlled_claim = _validated_claim(claim)
    resolved = resolve_m6_sqlite_canonical_physical_identity(
        connection=connection,
        source=controlled_claim.source,
        kind=controlled_claim.kind,
        artifact_id=controlled_claim.artifact_id,
        expected_run_id=expected_run_id,
        expected_manifest_id=expected_manifest_id,
    )
    if resolved.artifact_ref != controlled_claim:
        _fail(M6SQLitePhysicalDocumentFailureCode.CLAIM_MISMATCH)
    return resolved


__all__ = [
    "MAX_M6_SQLITE_CANONICAL_PHYSICAL_DOCUMENT_BYTES",
    "MAX_M6_SQLITE_CANONICAL_PHYSICAL_ROWS",
    "M6SQLiteCanonicalPhysicalDocument",
    "M6SQLitePhysicalDocumentError",
    "M6SQLitePhysicalDocumentFailureCode",
    "M6SQLitePhysicalRouteCapability",
    "m6_sqlite_physical_route_capability",
    "resolve_m6_sqlite_canonical_physical_document",
    "resolve_m6_sqlite_canonical_physical_identity",
]
