"""Bounded body-free SQLite queries for M3 model-document planning."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import NoReturn

from ._sqlite_m6_live_read_cut import (
    M6LiveDocumentColumn,
    M6LiveReader,
)
from ._sqlite_m6_upgrade_m3_model_plan import (
    MAX_M6_SQLITE_M3_MODEL_DOCUMENT_BYTES,
    MAX_M6_SQLITE_M3_MODEL_ROWS_PER_GROUP,
    M6SQLiteM3DocumentRoute,
    M6SQLiteM3ModelDocumentFailureCode,
    M6SQLiteM3SupportDocumentRoute,
    _M6SQLiteM3MetadataFailure,
)

_SQLITE_OCTET_LENGTH_MIN_VERSION = (3, 43, 0)
_USE_SQLITE_OCTET_LENGTH = sqlite3.sqlite_version_info >= _SQLITE_OCTET_LENGTH_MIN_VERSION
_LIMIT = MAX_M6_SQLITE_M3_MODEL_ROWS_PER_GROUP

_LIVE_DOCUMENT_ROUTE = {
    M6SQLiteM3DocumentRoute.MODEL_REQUEST: (M6LiveDocumentColumn.M3_MODEL_REQUEST_DOCUMENT),
    M6SQLiteM3DocumentRoute.MODEL_RESPONSE: (M6LiveDocumentColumn.M3_MODEL_RESPONSE_DOCUMENT),
    M6SQLiteM3DocumentRoute.MODEL_CACHE_REQUEST: (
        M6LiveDocumentColumn.M3_MODEL_CACHE_REQUEST_DOCUMENT
    ),
    M6SQLiteM3DocumentRoute.MODEL_CACHE_ENTRY: (M6LiveDocumentColumn.M3_MODEL_CACHE_ENTRY_DOCUMENT),
    M6SQLiteM3DocumentRoute.MODEL_PARSE_RECEIPT: (
        M6LiveDocumentColumn.M3_MODEL_PARSE_RECEIPT_DOCUMENT
    ),
    M6SQLiteM3DocumentRoute.PARSED_SCREENING_OUTPUT: (
        M6LiveDocumentColumn.M3_PARSED_SCREENING_OUTPUT_DOCUMENT
    ),
    M6SQLiteM3DocumentRoute.MODEL_CALL_FAILURE: (
        M6LiveDocumentColumn.M3_MODEL_CALL_FAILURE_DOCUMENT
    ),
    M6SQLiteM3DocumentRoute.MODEL_USAGE: M6LiveDocumentColumn.M3_MODEL_USAGE_DOCUMENT,
}

_DOCUMENT_SIZE_ALIAS = {
    M6SQLiteM3DocumentRoute.MODEL_REQUEST: "request_document_bytes",
    M6SQLiteM3DocumentRoute.MODEL_RESPONSE: "response_document_bytes",
    M6SQLiteM3DocumentRoute.MODEL_CACHE_REQUEST: "cache_request_document_bytes",
    M6SQLiteM3DocumentRoute.MODEL_CACHE_ENTRY: "cache_entry_document_bytes",
    M6SQLiteM3DocumentRoute.MODEL_PARSE_RECEIPT: "receipt_document_bytes",
    M6SQLiteM3DocumentRoute.PARSED_SCREENING_OUTPUT: "output_document_bytes",
    M6SQLiteM3DocumentRoute.MODEL_CALL_FAILURE: "failure_document_bytes",
    M6SQLiteM3DocumentRoute.MODEL_USAGE: "usage_document_bytes",
}

_DOCUMENT_TYPE_ALIAS = {
    route: alias.removesuffix("_bytes") + "_type" for route, alias in _DOCUMENT_SIZE_ALIAS.items()
}

_LIVE_SUPPORT_DOCUMENT_ROUTE = {
    M6SQLiteM3SupportDocumentRoute.BACKLOG_COMPLETION_RECEIPT: (
        M6LiveDocumentColumn.M3_BACKLOG_COMPLETION_RECEIPT_DOCUMENT
    ),
}


def _fail(reason_code: M6SQLiteM3ModelDocumentFailureCode) -> NoReturn:
    raise _M6SQLiteM3MetadataFailure(reason_code)


def _rows(
    connection: M6LiveReader,
    sql: str,
    parameters: tuple[object, ...],
    *,
    limit: int = _LIMIT,
) -> tuple[sqlite3.Row, ...]:
    """Fetch at most the sentinel row beyond the closed per-group budget."""

    cursor = connection.execute(sql, parameters)
    try:
        rows = tuple(cursor.fetchmany(limit + 1))
    finally:
        cursor.close()
    if len(rows) > limit:
        _fail(M6SQLiteM3ModelDocumentFailureCode.ROW_LIMIT_EXCEEDED)
    return rows


def _size_projection(column: str, alias: str) -> str:
    if _USE_SQLITE_OCTET_LENGTH:
        return f"octet_length({column}) AS {alias}"
    return f"NULL AS {alias}"


def document_bytes(
    connection: M6LiveReader,
    row: sqlite3.Row,
    route: M6SQLiteM3DocumentRoute,
) -> int:
    """Read only a metadata length, using the sealed old-SQLite BLOB route."""

    type_alias = _DOCUMENT_TYPE_ALIAS[route]
    if row[type_alias] != "text":
        _fail(M6SQLiteM3ModelDocumentFailureCode.DOCUMENT_INVALID)
    rowid = row["document_rowid"]
    if type(rowid) is not int or rowid <= 0:
        _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    value = row[_DOCUMENT_SIZE_ALIAS[route]]
    if not _USE_SQLITE_OCTET_LENGTH:
        value = connection.document_octet_length(_LIVE_DOCUMENT_ROUTE[route], rowid)
    if type(value) is not int or value <= 0:
        _fail(M6SQLiteM3ModelDocumentFailureCode.DOCUMENT_INVALID)
    if value > MAX_M6_SQLITE_M3_MODEL_DOCUMENT_BYTES:
        _fail(M6SQLiteM3ModelDocumentFailureCode.DOCUMENT_TOO_LARGE)
    return value


def support_document_bytes(
    connection: M6LiveReader,
    row: sqlite3.Row,
    route: M6SQLiteM3SupportDocumentRoute,
) -> int:
    """Preflight one allowlisted canonical support body without materializing it."""

    if row["support_document_type"] != "text":
        _fail(M6SQLiteM3ModelDocumentFailureCode.DOCUMENT_INVALID)
    rowid = row["support_rowid"]
    if type(rowid) is not int or rowid <= 0:
        _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    value = row["support_document_bytes"]
    if not _USE_SQLITE_OCTET_LENGTH:
        value = connection.document_octet_length(_LIVE_SUPPORT_DOCUMENT_ROUTE[route], rowid)
    if type(value) is not int or value <= 0:
        _fail(M6SQLiteM3ModelDocumentFailureCode.DOCUMENT_INVALID)
    if value > MAX_M6_SQLITE_M3_MODEL_DOCUMENT_BYTES:
        _fail(M6SQLiteM3ModelDocumentFailureCode.DOCUMENT_TOO_LARGE)
    return value


@dataclass(frozen=True, slots=True)
class _M3PrimaryRows:
    claims: tuple[sqlite3.Row, ...]
    responses: tuple[sqlite3.Row, ...]
    caches: tuple[sqlite3.Row, ...]
    receipts: tuple[sqlite3.Row, ...]
    outputs: tuple[sqlite3.Row, ...]
    failures: tuple[sqlite3.Row, ...]
    usages: tuple[sqlite3.Row, ...]


def read_primary_rows(
    connection: M6LiveReader,
    *,
    run_id: str,
    case_id: str,
) -> _M3PrimaryRows:
    """Enumerate all seven Case-scoped M3 tables without an Observation IN-list."""

    request_size = _size_projection("request_json", "request_document_bytes")
    response_size = _size_projection("response_json", "response_document_bytes")
    cache_request_size = _size_projection(
        "request_json",
        "cache_request_document_bytes",
    )
    cache_entry_size = _size_projection("entry_json", "cache_entry_document_bytes")
    receipt_size = _size_projection("receipt_json", "receipt_document_bytes")
    output_size = _size_projection("output_json", "output_document_bytes")
    failure_size = _size_projection("authority_json", "failure_document_bytes")
    usage_size = _size_projection("usage_json", "usage_document_bytes")
    scope = (run_id, case_id)
    claims = _rows(
        connection,
        f"""
        SELECT rowid AS document_rowid,
               run_id, request_id, request_sha256, cache_key, case_id,
               evidence_pack_id, evidence_pack_version, purpose,
               model_manifest_id, manifest_id, request_document_sha256,
               status, owner_token_sha256, lease_expires_at, takeover_count,
               created_at, response_id, completed_at,
               typeof(request_json) AS request_document_type,
               {request_size}
        FROM model_call_claims
        WHERE run_id = ? AND case_id = ?
        ORDER BY request_id
        LIMIT {_LIMIT + 1}
        """,
        scope,
    )
    responses = _rows(
        connection,
        f"""
        SELECT rowid AS document_rowid,
               run_id, response_id, case_id, evidence_pack_id,
               evidence_pack_version, request_id, request_sha256, cache_key,
               purpose, attempt_index, raw_response_ref, content_sha256,
               size_bytes, model_manifest_id, manifest_id, document_sha256,
               typeof(response_json) AS response_document_type,
               {response_size}
        FROM model_responses
        WHERE run_id = ? AND case_id = ?
        ORDER BY request_id, response_id
        LIMIT {_LIMIT + 1}
        """,
        scope,
    )
    caches = _rows(
        connection,
        f"""
        SELECT rowid AS document_rowid,
               run_id, cache_key, cache_entry_id, case_id, evidence_pack_id,
               evidence_pack_version, request_id, request_sha256, response_id,
               response_content_sha256, model_manifest_id, prompt_manifest_id,
               output_schema_sha256, manifest_id, request_document_sha256,
               document_sha256,
               typeof(request_json) AS cache_request_document_type,
               {cache_request_size},
               typeof(entry_json) AS cache_entry_document_type,
               {cache_entry_size}
        FROM model_cache
        WHERE run_id = ? AND case_id = ?
        ORDER BY request_id, cache_entry_id
        LIMIT {_LIMIT + 1}
        """,
        scope,
    )
    receipts = _rows(
        connection,
        f"""
        SELECT rowid AS document_rowid,
               run_id, parse_receipt_id, case_id, evidence_pack_id,
               evidence_pack_version, request_id, response_id, attempt_index,
               status, parsed_output_id, parsed_output_sha256,
               repair_request_id, manifest_id, document_sha256,
               typeof(receipt_json) AS receipt_document_type,
               {receipt_size}
        FROM model_parse_receipts
        WHERE run_id = ? AND case_id = ?
        ORDER BY request_id, parse_receipt_id
        LIMIT {_LIMIT + 1}
        """,
        scope,
    )
    outputs = _rows(
        connection,
        f"""
        SELECT rowid AS document_rowid,
               run_id, parsed_output_id, case_id, evidence_pack_id,
               evidence_pack_version, request_id, response_id,
               response_content_sha256, output_schema_sha256,
               model_payload_sha256, parsed_output_sha256, manifest_id,
               document_sha256,
               typeof(output_json) AS output_document_type,
               {output_size}
        FROM parsed_screening_outputs
        WHERE run_id = ? AND case_id = ?
        ORDER BY request_id, parsed_output_id
        LIMIT {_LIMIT + 1}
        """,
        scope,
    )
    failures = _rows(
        connection,
        f"""
        SELECT rowid AS document_rowid,
               run_id, authority_id, request_id, request_sha256,
               request_document_sha256, cache_key, case_id, evidence_pack_id,
               evidence_pack_version, purpose, model_manifest_id,
               claim_owner_sha256, claim_lease_expires_at,
               claim_takeover_count, failure_code, delivery_certainty,
               backlog_reason_code, backlog_item_id, backlog_version,
               backlog_status, backlog_attempt_count, retry_generation,
               closure_kind, completion_receipt_id, closure_case_revision,
               closure_audit_sequence, closure_audit_entry_hash, manifest_id,
               recorded_at, document_sha256,
               typeof(authority_json) AS failure_document_type,
               {failure_size}
        FROM model_call_failure_authorities
        WHERE run_id = ? AND case_id = ?
        ORDER BY request_id, claim_takeover_count, authority_id
        LIMIT {_LIMIT + 1}
        """,
        scope,
    )
    usages = _rows(
        connection,
        f"""
        SELECT rowid AS document_rowid,
               run_id, request_id, response_id, case_id, case_revision,
               consumer_kind, consumer_id, accounted_at, input_images,
               input_pixels, input_tokens, output_tokens,
               provider_latency_ms, retries, estimated_cost, document_sha256,
               typeof(usage_json) AS usage_document_type,
               {usage_size}
        FROM model_call_usage_accounting
        WHERE run_id = ? AND case_id = ?
        ORDER BY request_id
        LIMIT {_LIMIT + 1}
        """,
        scope,
    )
    return _M3PrimaryRows(
        claims=claims,
        responses=responses,
        caches=caches,
        receipts=receipts,
        outputs=outputs,
        failures=failures,
        usages=usages,
    )


def read_run_row(
    connection: M6LiveReader,
    *,
    run_id: str,
) -> tuple[sqlite3.Row, ...]:
    return _rows(
        connection,
        """
        SELECT rowid AS support_rowid, run_id, manifest_id
        FROM runs WHERE run_id = ?
        ORDER BY run_id LIMIT 2
        """,
        (run_id,),
        limit=1,
    )


def read_pack_row(
    connection: M6LiveReader,
    *,
    run_id: str,
    case_id: str,
    pack_id: str,
    version: int,
) -> tuple[sqlite3.Row, ...]:
    return _rows(
        connection,
        """
        SELECT rowid AS support_rowid, run_id, pack_id, case_id, manifest_id,
               version, complete, pack_input_sha256, closure_input_sha256,
               document_sha256, created_audit_sequence
        FROM evidence_packs
        WHERE run_id = ? AND case_id = ? AND pack_id = ? AND version = ?
        LIMIT 2
        """,
        (run_id, case_id, pack_id, version),
        limit=1,
    )


def read_case_version_row(
    connection: M6LiveReader,
    *,
    run_id: str,
    case_id: str,
    revision: int,
) -> tuple[sqlite3.Row, ...]:
    return _rows(
        connection,
        """
        SELECT rowid AS support_rowid, run_id, case_id, revision, status,
               document_sha256, audit_sequence
        FROM case_versions
        WHERE run_id = ? AND case_id = ? AND revision = ?
        LIMIT 2
        """,
        (run_id, case_id, revision),
        limit=1,
    )


def read_audit_row(
    connection: M6LiveReader,
    *,
    run_id: str,
    sequence: int,
) -> tuple[sqlite3.Row, ...]:
    return _rows(
        connection,
        """
        SELECT rowid AS support_rowid, run_id, sequence, manifest_id, action,
               object_kind, object_id, before_sha256, after_sha256, entry_hash
        FROM audit_entries
        WHERE run_id = ? AND sequence = ?
        LIMIT 2
        """,
        (run_id, sequence),
        limit=1,
    )


def read_screening_row(
    connection: M6LiveReader,
    *,
    run_id: str,
    case_id: str,
    screening_id: str,
) -> tuple[sqlite3.Row, ...]:
    return _rows(
        connection,
        """
        SELECT rowid AS support_rowid, run_id, screening_id, case_id, version,
               evidence_pack_id, evidence_pack_version, parsed_output_id,
               manifest_id, audit_sequence, document_sha256
        FROM screening_results
        WHERE run_id = ? AND case_id = ? AND screening_id = ?
        LIMIT 2
        """,
        (run_id, case_id, screening_id),
        limit=1,
    )


def read_backlog_item_row(
    connection: M6LiveReader,
    *,
    run_id: str,
    case_id: str,
    item_id: str,
) -> tuple[sqlite3.Row, ...]:
    return _rows(
        connection,
        """
        SELECT rowid AS support_rowid, run_id, item_id, case_id, stage, role,
               reason_code, stage_input_kind, stage_input_id,
               stage_input_sha256, max_attempts, manifest_id,
               initial_document_sha256
        FROM backlog_items
        WHERE run_id = ? AND case_id = ? AND item_id = ?
        LIMIT 2
        """,
        (run_id, case_id, item_id),
        limit=1,
    )


def read_backlog_version_row(
    connection: M6LiveReader,
    *,
    run_id: str,
    item_id: str,
    version: int,
) -> tuple[sqlite3.Row, ...]:
    return _rows(
        connection,
        """
        SELECT rowid AS support_rowid, run_id, item_id, version, status,
               attempt_count, lease_id, lease_owner_sha256, lease_expires_at,
               document_sha256, retry_generation
        FROM backlog_item_versions
        WHERE run_id = ? AND item_id = ? AND version = ?
        LIMIT 2
        """,
        (run_id, item_id, version),
        limit=1,
    )


def read_backlog_head_row(
    connection: M6LiveReader,
    *,
    run_id: str,
    item_id: str,
) -> tuple[sqlite3.Row, ...]:
    return _rows(
        connection,
        """
        SELECT rowid AS support_rowid, run_id, item_id, current_version
        FROM backlog_heads
        WHERE run_id = ? AND item_id = ?
        LIMIT 2
        """,
        (run_id, item_id),
        limit=1,
    )


def read_completion_row(
    connection: M6LiveReader,
    *,
    run_id: str,
    case_id: str,
    receipt_id: str,
) -> tuple[sqlite3.Row, ...]:
    receipt_size = _size_projection("receipt_json", "support_document_bytes")
    return _rows(
        connection,
        f"""
        SELECT rowid AS support_rowid, run_id, receipt_id, item_id, case_id,
               outcome_kind, outcome_id, lease_identity_sha256, lease_id,
               attempt_count, retry_generation, backlog_status,
               backlog_version, completion_kind, completion_id,
               completion_case_status, completion_case_revision,
               completion_audit_sequence, completion_audit_entry_hash,
               manifest_id, document_sha256,
               typeof(receipt_json) AS support_document_type,
               {receipt_size}
        FROM backlog_completion_receipts
        WHERE run_id = ? AND case_id = ? AND receipt_id = ?
        LIMIT 2
        """,
        (run_id, case_id, receipt_id),
        limit=1,
    )


def read_backlog_completions_for_revision(
    connection: M6LiveReader,
    *,
    run_id: str,
    case_id: str,
    item_id: str,
    case_revision: int,
) -> tuple[sqlite3.Row, ...]:
    receipt_size = _size_projection("receipt_json", "support_document_bytes")
    return _rows(
        connection,
        f"""
        SELECT rowid AS support_rowid, run_id, receipt_id, item_id, case_id,
               outcome_kind, outcome_id, lease_identity_sha256, lease_id,
               attempt_count, retry_generation, backlog_status,
               backlog_version, completion_kind, completion_id,
               completion_case_status, completion_case_revision,
               completion_audit_sequence, completion_audit_entry_hash,
               manifest_id, document_sha256,
               typeof(receipt_json) AS support_document_type,
               {receipt_size}
        FROM backlog_completion_receipts
        WHERE run_id = ? AND case_id = ? AND item_id = ?
          AND completion_case_revision = ?
        ORDER BY receipt_id
        LIMIT {_LIMIT + 1}
        """,
        (run_id, case_id, item_id, case_revision),
    )


def read_backlog_success_completion_for_revision(
    connection: M6LiveReader,
    *,
    run_id: str,
    case_id: str,
    case_revision: int,
) -> tuple[sqlite3.Row, ...]:
    """Resolve the optional retry-success receipt for one Case transition."""

    receipt_size = _size_projection("receipt_json", "support_document_bytes")
    return _rows(
        connection,
        f"""
        SELECT rowid AS support_rowid, run_id, receipt_id, item_id, case_id,
               outcome_kind, outcome_id, lease_identity_sha256, lease_id,
               attempt_count, retry_generation, backlog_status,
               backlog_version, completion_kind, completion_id,
               completion_case_status, completion_case_revision,
               completion_audit_sequence, completion_audit_entry_hash,
               manifest_id, document_sha256,
               typeof(receipt_json) AS support_document_type,
               {receipt_size}
        FROM backlog_completion_receipts
        WHERE run_id = ? AND case_id = ? AND outcome_kind = 'SUCCESS'
          AND completion_case_revision = ?
        ORDER BY receipt_id
        LIMIT 2
        """,
        (run_id, case_id, case_revision),
    )
