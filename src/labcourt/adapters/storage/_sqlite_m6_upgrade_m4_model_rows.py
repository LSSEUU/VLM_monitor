"""Bounded body-free SQLite queries for M4 model-document planning."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import NoReturn

from ._sqlite_m6_live_read_cut import M6LiveDocumentColumn, M6LiveReader
from ._sqlite_m6_upgrade_m4_model_plan import (
    MAX_M6_SQLITE_M4_MODEL_DOCUMENT_BYTES,
    MAX_M6_SQLITE_M4_MODEL_ROWS_PER_GROUP,
    M6SQLiteM4DocumentRoute,
    M6SQLiteM4ModelDocumentFailureCode,
    M6SQLiteM4SupportDocumentRoute,
    _M6SQLiteM4MetadataFailure,
)

_SQLITE_OCTET_LENGTH_MIN_VERSION = (3, 43, 0)
_USE_SQLITE_OCTET_LENGTH = sqlite3.sqlite_version_info >= _SQLITE_OCTET_LENGTH_MIN_VERSION
_LIMIT = MAX_M6_SQLITE_M4_MODEL_ROWS_PER_GROUP

_LIVE_DOCUMENT_ROUTE = {
    M6SQLiteM4DocumentRoute.MODEL_REQUEST: M6LiveDocumentColumn.M4_MODEL_REQUEST_DOCUMENT,
    M6SQLiteM4DocumentRoute.MODEL_RESPONSE: (M6LiveDocumentColumn.M4_MODEL_RESPONSE_DOCUMENT),
    M6SQLiteM4DocumentRoute.MODEL_CACHE_REQUEST: (
        M6LiveDocumentColumn.M4_MODEL_CACHE_REQUEST_DOCUMENT
    ),
    M6SQLiteM4DocumentRoute.MODEL_CACHE_ENTRY: (M6LiveDocumentColumn.M4_MODEL_CACHE_ENTRY_DOCUMENT),
    M6SQLiteM4DocumentRoute.MODEL_PARSE_RECEIPT: (
        M6LiveDocumentColumn.M4_MODEL_PARSE_RECEIPT_DOCUMENT
    ),
    M6SQLiteM4DocumentRoute.ROLE_OUTPUT: M6LiveDocumentColumn.M4_ROLE_OUTPUT_DOCUMENT,
    M6SQLiteM4DocumentRoute.MODEL_CALL_FAILURE: (
        M6LiveDocumentColumn.M4_MODEL_CALL_FAILURE_DOCUMENT
    ),
    M6SQLiteM4DocumentRoute.MODEL_USAGE: M6LiveDocumentColumn.M4_MODEL_USAGE_DOCUMENT,
}

_DOCUMENT_SIZE_ALIAS = {
    M6SQLiteM4DocumentRoute.MODEL_REQUEST: "request_document_bytes",
    M6SQLiteM4DocumentRoute.MODEL_RESPONSE: "response_document_bytes",
    M6SQLiteM4DocumentRoute.MODEL_CACHE_REQUEST: "cache_request_document_bytes",
    M6SQLiteM4DocumentRoute.MODEL_CACHE_ENTRY: "cache_entry_document_bytes",
    M6SQLiteM4DocumentRoute.MODEL_PARSE_RECEIPT: "receipt_document_bytes",
    M6SQLiteM4DocumentRoute.ROLE_OUTPUT: "output_document_bytes",
    M6SQLiteM4DocumentRoute.MODEL_CALL_FAILURE: "failure_document_bytes",
    M6SQLiteM4DocumentRoute.MODEL_USAGE: "usage_document_bytes",
}
_DOCUMENT_TYPE_ALIAS = {
    route: alias.removesuffix("_bytes") + "_type" for route, alias in _DOCUMENT_SIZE_ALIAS.items()
}

_LIVE_SUPPORT_DOCUMENT_ROUTE = {
    M6SQLiteM4SupportDocumentRoute.HEARING_SESSION: (
        M6LiveDocumentColumn.M4_HEARING_SESSION_DOCUMENT
    ),
    M6SQLiteM4SupportDocumentRoute.HEARING_CYCLE: (M6LiveDocumentColumn.M4_HEARING_CYCLE_DOCUMENT),
    M6SQLiteM4SupportDocumentRoute.PRECEDENT_RETRIEVAL: (
        M6LiveDocumentColumn.M4_PRECEDENT_RETRIEVAL_DOCUMENT
    ),
    M6SQLiteM4SupportDocumentRoute.HEARING_ROUND: (M6LiveDocumentColumn.M4_HEARING_ROUND_DOCUMENT),
    M6SQLiteM4SupportDocumentRoute.HEARING_CHECKPOINT: (
        M6LiveDocumentColumn.M4_HEARING_CHECKPOINT_DOCUMENT
    ),
    M6SQLiteM4SupportDocumentRoute.BACKLOG_ITEM: (M6LiveDocumentColumn.M4_BACKLOG_ITEM_DOCUMENT),
    M6SQLiteM4SupportDocumentRoute.BACKLOG_ITEM_VERSION: (
        M6LiveDocumentColumn.M4_BACKLOG_ITEM_VERSION_DOCUMENT
    ),
    M6SQLiteM4SupportDocumentRoute.BACKLOG_RETRY_OUTCOME: (
        M6LiveDocumentColumn.M4_BACKLOG_RETRY_OUTCOME_DOCUMENT
    ),
    M6SQLiteM4SupportDocumentRoute.BACKLOG_COMPLETION_RECEIPT: (
        M6LiveDocumentColumn.M4_BACKLOG_COMPLETION_RECEIPT_DOCUMENT
    ),
    M6SQLiteM4SupportDocumentRoute.STRICT_PARSE_FAILURE_ATTEMPT: (
        M6LiveDocumentColumn.M4_STRICT_PARSE_FAILURE_ATTEMPT_DOCUMENT
    ),
    M6SQLiteM4SupportDocumentRoute.STRICT_PARSE_FAILURE_PROOF: (
        M6LiveDocumentColumn.M4_STRICT_PARSE_FAILURE_PROOF_DOCUMENT
    ),
    M6SQLiteM4SupportDocumentRoute.HEARING_HUMAN_REVIEW_RECEIPT: (
        M6LiveDocumentColumn.M4_HEARING_HUMAN_REVIEW_RECEIPT_DOCUMENT
    ),
}


def _fail(reason_code: M6SQLiteM4ModelDocumentFailureCode) -> NoReturn:
    raise _M6SQLiteM4MetadataFailure(reason_code)


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
        _fail(M6SQLiteM4ModelDocumentFailureCode.ROW_LIMIT_EXCEEDED)
    return rows


def _size_projection(column: str, alias: str) -> str:
    if _USE_SQLITE_OCTET_LENGTH:
        return f"octet_length({column}) AS {alias}"
    return f"NULL AS {alias}"


def document_bytes(
    connection: M6LiveReader,
    row: sqlite3.Row,
    route: M6SQLiteM4DocumentRoute,
) -> int:
    """Read a canonical body length without materializing the body."""

    if row[_DOCUMENT_TYPE_ALIAS[route]] != "text":
        _fail(M6SQLiteM4ModelDocumentFailureCode.DOCUMENT_INVALID)
    rowid = row["document_rowid"]
    if type(rowid) is not int or rowid <= 0:
        _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    value = row[_DOCUMENT_SIZE_ALIAS[route]]
    if not _USE_SQLITE_OCTET_LENGTH:
        value = connection.document_octet_length(_LIVE_DOCUMENT_ROUTE[route], rowid)
    if type(value) is not int or value <= 0:
        _fail(M6SQLiteM4ModelDocumentFailureCode.DOCUMENT_INVALID)
    if value > MAX_M6_SQLITE_M4_MODEL_DOCUMENT_BYTES:
        _fail(M6SQLiteM4ModelDocumentFailureCode.DOCUMENT_TOO_LARGE)
    return value


def support_document_bytes(
    connection: M6LiveReader,
    row: sqlite3.Row,
    route: M6SQLiteM4SupportDocumentRoute,
) -> int:
    """Read one causal support-body length through an exact closed route."""

    if row["support_document_type"] != "text":
        _fail(M6SQLiteM4ModelDocumentFailureCode.DOCUMENT_INVALID)
    rowid = row["support_rowid"]
    if type(rowid) is not int or rowid <= 0:
        _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    value = row["support_document_bytes"]
    if not _USE_SQLITE_OCTET_LENGTH:
        value = connection.document_octet_length(
            _LIVE_SUPPORT_DOCUMENT_ROUTE[route],
            rowid,
        )
    if type(value) is not int or value <= 0:
        _fail(M6SQLiteM4ModelDocumentFailureCode.DOCUMENT_INVALID)
    if value > MAX_M6_SQLITE_M4_MODEL_DOCUMENT_BYTES:
        _fail(M6SQLiteM4ModelDocumentFailureCode.DOCUMENT_TOO_LARGE)
    return value


@dataclass(frozen=True, slots=True)
class _M4PrimaryRows:
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
) -> _M4PrimaryRows:
    """Enumerate all seven Case-scoped M4 call tables without reading bodies."""

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
               run_id, request_id, request_sha256, cache_key, hearing_id,
               cycle_scope_id, cycle_scope_sha256, case_id, role, purpose,
               attempt_index, call_generation, backlog_item_id,
               retry_generation, reserved_images, reserved_pixels,
               evidence_pack_id, evidence_pack_version, model_manifest_id,
               prompt_manifest_id, manifest_id, request_document_sha256,
               status, owner_token_sha256, lease_expires_at, takeover_count,
               created_at, response_id, completed_at,
               typeof(request_json) AS request_document_type,
               {request_size}
        FROM m4_model_call_claims
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
               run_id, response_id, request_id, request_sha256, cache_key,
               hearing_id, cycle_scope_id, cycle_scope_sha256, case_id, role,
               purpose, attempt_index, retry_generation, raw_response_ref,
               content_sha256, size_bytes, model_manifest_id, manifest_id,
               document_sha256,
               typeof(response_json) AS response_document_type,
               {response_size}
        FROM m4_model_responses
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
               run_id, cache_key, cache_entry_id, hearing_id, cycle_scope_id,
               cycle_scope_sha256, case_id, role, request_id, request_sha256,
               response_id, response_content_sha256, model_manifest_id,
               prompt_manifest_id, output_schema_sha256, manifest_id,
               request_document_sha256, document_sha256,
               typeof(request_json) AS cache_request_document_type,
               {cache_request_size},
               typeof(entry_json) AS cache_entry_document_type,
               {cache_entry_size}
        FROM m4_model_cache
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
               run_id, parse_receipt_id, hearing_id, cycle_scope_id,
               cycle_scope_sha256, case_id, role, request_id, request_sha256,
               response_id, response_content_sha256, attempt_index,
               parser_version, output_schema_sha256, status,
               parsed_output_id, repair_request_id, manifest_id,
               document_sha256,
               typeof(receipt_json) AS receipt_document_type,
               {receipt_size}
        FROM m4_model_parse_receipts
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
               run_id, parsed_output_id, hearing_id, cycle_scope_id,
               cycle_scope_sha256, case_id, prior_acquisition_rounds,
               prior_rework_rounds, current_pack_id, current_pack_version,
               role, payload_kind, request_id, response_id, parse_receipt_id,
               response_content_sha256, output_schema_sha256,
               prompt_manifest_id, model_manifest_id, prosecutor_output_id,
               defender_output_id, precedent_retrieval_degraded,
               precedent_retrieval_receipt_id,
               precedent_retrieval_receipt_sha256, initial_trigger_review_id,
               rework_review_id, payload_sha256, manifest_id, document_sha256,
               typeof(output_json) AS output_document_type,
               {output_size}
        FROM m4_parsed_hearing_outputs
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
               request_document_sha256, cache_key, hearing_id, cycle_scope_id,
               cycle_scope_sha256, case_id, role, source_checkpoint_id,
               source_checkpoint_sha256, source_checkpoint_version,
               lease_identity_sha256, lease_id, backlog_attempt_count,
               retry_generation, claim_owner_sha256,
               claim_lease_expires_at, claim_takeover_count, failure_code,
               delivery_certainty, provider_response_content_sha256,
               reserved_images, reserved_pixels, disclosed_images,
               disclosed_pixels, input_tokens, output_tokens, latency_ms,
               estimated_cost, backlog_item_id, backlog_reason_code,
               backlog_version, backlog_status, closure_kind,
               completion_receipt_id, closure_case_revision,
               closure_audit_sequence, closure_audit_entry_hash, manifest_id,
               recorded_at, document_sha256,
               typeof(authority_json) AS failure_document_type,
               {failure_size}
        FROM m4_model_call_failure_authorities
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
               run_id, usage_receipt_id, request_id, response_id, hearing_id,
               cycle_scope_id, cycle_scope_sha256, case_id, role,
               accounted_at, input_images, input_pixels, input_tokens,
               output_tokens, provider_latency_ms, retries, estimated_cost,
               manifest_id, document_sha256,
               typeof(usage_json) AS usage_document_type,
               {usage_size}
        FROM m4_hearing_usage_receipts
        WHERE run_id = ? AND case_id = ?
        ORDER BY request_id, usage_receipt_id
        LIMIT {_LIMIT + 1}
        """,
        scope,
    )
    return _M4PrimaryRows(
        claims=claims,
        responses=responses,
        caches=caches,
        receipts=receipts,
        outputs=outputs,
        failures=failures,
        usages=usages,
    )


@dataclass(frozen=True, slots=True)
class _M4HearingSupportRows:
    sessions: tuple[sqlite3.Row, ...]
    cycles: tuple[sqlite3.Row, ...]
    retrievals: tuple[sqlite3.Row, ...]
    rounds: tuple[sqlite3.Row, ...]
    checkpoints: tuple[sqlite3.Row, ...]


def read_hearing_support_rows(
    connection: M6LiveReader,
    *,
    run_id: str,
    case_id: str,
) -> _M4HearingSupportRows:
    """Enumerate the five core M4 hearing support tables without JSON bodies."""

    hearing_size = _size_projection("hearing_json", "support_document_bytes")
    cycle_size = _size_projection("cycle_json", "support_document_bytes")
    retrieval_size = _size_projection("receipt_json", "support_document_bytes")
    round_size = _size_projection("round_json", "support_document_bytes")
    checkpoint_size = _size_projection("checkpoint_json", "support_document_bytes")
    scope = (run_id, case_id)
    sessions = _rows(
        connection,
        f"""
        SELECT rowid AS support_rowid,
               run_id, hearing_id, case_id, screening_id, entry_status,
               trigger_review_id, initial_pack_id, initial_pack_version,
               max_acquisition_rounds, max_rework_rounds, max_total_images,
               max_total_output_tokens, max_judge_cycles,
               hearing_prompt_bundle_sha256, prosecutor_model_manifest_id,
               defender_model_manifest_id, judge_model_manifest_id,
               manifest_id, created_audit_sequence,
               document_sha256 AS body_commitment_sha256,
               typeof(hearing_json) AS support_document_type,
               {hearing_size}
        FROM m4_hearings
        WHERE run_id = ? AND case_id = ?
        ORDER BY hearing_id
        LIMIT {_LIMIT + 1}
        """,
        scope,
    )
    cycles = _rows(
        connection,
        f"""
        SELECT rowid AS support_rowid,
               run_id, cycle_id, cycle_sha256, hearing_id, case_id,
               cycle_index, prior_acquisition_rounds, prior_rework_rounds,
               cycle_pack_id, cycle_pack_version, initial_trigger_review_id,
               rework_review_id, manifest_id, created_audit_sequence,
               cycle_sha256 AS body_commitment_sha256,
               typeof(cycle_json) AS support_document_type,
               {cycle_size}
        FROM m4_hearing_cycles
        WHERE run_id = ? AND case_id = ?
        ORDER BY hearing_id, cycle_index, cycle_id
        LIMIT {_LIMIT + 1}
        """,
        scope,
    )
    retrievals = _rows(
        connection,
        f"""
        SELECT rowid AS support_rowid,
               run_id, retrieval_receipt_id, hearing_id, cycle_scope_id,
               cycle_scope_sha256, case_id, prior_acquisition_rounds,
               prior_rework_rounds, current_pack_id, current_pack_version,
               evidence_class, violation_type, rule_version, top_k,
               initial_trigger_review_id, rework_review_id,
               candidate_snapshot_sha256, visible_snapshot_sha256,
               retrieval_status, degraded_reason,
               precedent_retrieval_degraded, retriever_version,
               retriever_manifest_id, query_sha256,
               embedding_model_manifest_id, manifest_id, document_sha256,
               document_sha256 AS body_commitment_sha256,
               typeof(receipt_json) AS support_document_type,
               {retrieval_size}
        FROM m4_precedent_retrieval_receipts
        WHERE run_id = ? AND case_id = ?
        ORDER BY hearing_id, cycle_scope_id, retrieval_receipt_id
        LIMIT {_LIMIT + 1}
        """,
        scope,
    )
    rounds = _rows(
        connection,
        f"""
        SELECT rowid AS support_rowid,
               run_id, round_id, hearing_id, cycle_scope_id,
               cycle_scope_sha256, case_id, round_index,
               prior_acquisition_rounds, prior_rework_rounds,
               current_pack_id, current_pack_version,
               precedent_retrieval_degraded, retrieval_receipt_id,
               retrieval_receipt_sha256, initial_trigger_review_id,
               rework_review_id, prosecutor_output_id, defender_output_id,
               judge_output_id, acquisition_request_id, tool_receipt_id,
               resulting_pack_id, resulting_pack_version, manifest_id,
               round_id AS body_commitment_sha256,
               typeof(round_json) AS support_document_type,
               {round_size}
        FROM m4_hearing_rounds
        WHERE run_id = ? AND case_id = ?
        ORDER BY hearing_id, round_index, round_id
        LIMIT {_LIMIT + 1}
        """,
        scope,
    )
    checkpoints = _rows(
        connection,
        f"""
        SELECT rowid AS support_rowid,
               run_id, checkpoint_id, checkpoint_sha256, hearing_id,
               hearing_sha256, cycle_scope_id, cycle_scope_sha256, case_id,
               version, phase, judge_cycle, prior_acquisition_rounds,
               prior_rework_rounds, cycle_pack_id, cycle_pack_version,
               current_pack_id, current_pack_version, previous_checkpoint_id,
               previous_checkpoint_sha256, previous_phase,
               initial_trigger_review_id, cycle_trigger_review_id,
               retrieval_receipt_id, retrieval_receipt_sha256,
               prosecutor_output_id, defender_output_id, judge_output_id,
               acquisition_request_id, tool_receipt_id, procedural_review_id,
               human_review_receipt_id, human_review_receipt_sha256,
               human_review_reason, manifest_id,
               checkpoint_sha256 AS body_commitment_sha256,
               typeof(checkpoint_json) AS support_document_type,
               {checkpoint_size}
        FROM m4_hearing_checkpoints
        WHERE run_id = ? AND case_id = ?
        ORDER BY hearing_id, version, checkpoint_id
        LIMIT {_LIMIT + 1}
        """,
        scope,
    )
    return _M4HearingSupportRows(
        sessions=sessions,
        cycles=cycles,
        retrievals=retrievals,
        rounds=rounds,
        checkpoints=checkpoints,
    )


@dataclass(frozen=True, slots=True)
class _M4BacklogSupportRows:
    items: tuple[sqlite3.Row, ...]
    versions: tuple[sqlite3.Row, ...]
    heads: tuple[sqlite3.Row, ...]
    retry_outcomes: tuple[sqlite3.Row, ...]
    completions: tuple[sqlite3.Row, ...]
    strict_attempts: tuple[sqlite3.Row, ...]
    strict_proofs: tuple[sqlite3.Row, ...]
    human_reviews: tuple[sqlite3.Row, ...]


def read_backlog_support_rows(
    connection: M6LiveReader,
    *,
    run_id: str,
    case_id: str,
) -> _M4BacklogSupportRows:
    """Enumerate Case-scoped hearing backlog support without reading bodies."""

    item_size = _size_projection("initial_json", "support_document_bytes")
    version_size = _size_projection("version.item_json", "support_document_bytes")
    outcome_size = _size_projection("outcome_json", "support_document_bytes")
    completion_size = _size_projection("receipt_json", "support_document_bytes")
    attempt_size = _size_projection("attempt_json", "support_document_bytes")
    proof_size = _size_projection("proof_json", "support_document_bytes")
    human_size = _size_projection("receipt_json", "support_document_bytes")
    scope = (run_id, case_id)
    items = _rows(
        connection,
        f"""
        SELECT rowid AS support_rowid,
               run_id, item_id, case_id, stage, role, reason_code,
               stage_input_kind, stage_input_id, stage_input_sha256,
               max_attempts, manifest_id, initial_document_sha256,
               initial_document_sha256 AS body_commitment_sha256,
               typeof(initial_json) AS support_document_type,
               {item_size}
        FROM backlog_items
        WHERE run_id = ? AND case_id = ? AND stage = 'HEARING'
        ORDER BY item_id
        LIMIT {_LIMIT + 1}
        """,
        scope,
    )
    versions = _rows(
        connection,
        f"""
        SELECT version.rowid AS support_rowid,
               version.run_id, version.item_id, version.version,
               version.status, version.attempt_count, version.lease_id,
               version.lease_owner_sha256, version.lease_expires_at,
               version.document_sha256, version.retry_generation,
               version.document_sha256 AS body_commitment_sha256,
               typeof(version.item_json) AS support_document_type,
               {version_size}
        FROM backlog_item_versions AS version
        JOIN backlog_items AS item
          ON item.run_id = version.run_id AND item.item_id = version.item_id
        WHERE version.run_id = ? AND item.case_id = ? AND item.stage = 'HEARING'
        ORDER BY version.item_id, version.version
        LIMIT {_LIMIT + 1}
        """,
        scope,
    )
    heads = _rows(
        connection,
        f"""
        SELECT head.rowid AS support_rowid,
               head.run_id, head.item_id, head.current_version
        FROM backlog_heads AS head
        JOIN backlog_items AS item
          ON item.run_id = head.run_id AND item.item_id = head.item_id
        WHERE head.run_id = ? AND item.case_id = ? AND item.stage = 'HEARING'
        ORDER BY head.item_id
        LIMIT {_LIMIT + 1}
        """,
        scope,
    )
    retry_outcomes = _rows(
        connection,
        f"""
        SELECT rowid AS support_rowid,
               run_id, outcome_id, outcome_kind, hearing_id, cycle_scope_id,
               cycle_scope_sha256, case_id, role, backlog_item_id,
               lease_identity_sha256, lease_id, lease_attempt_count,
               retry_generation, source_checkpoint_id,
               source_checkpoint_sha256, source_checkpoint_version,
               request_id, request_sha256, response_id, parse_receipt_id,
               parsed_output_id, next_checkpoint_id, next_checkpoint_sha256,
               next_checkpoint_version, reason_code, next_status,
               strict_parse_failure_proof_id, human_review_receipt_id,
               next_retry_generation, manifest_id, document_sha256,
               document_sha256 AS body_commitment_sha256,
               typeof(outcome_json) AS support_document_type,
               {outcome_size}
        FROM m4_hearing_backlog_retry_outcomes
        WHERE run_id = ? AND case_id = ?
        ORDER BY backlog_item_id, source_checkpoint_version, outcome_id
        LIMIT {_LIMIT + 1}
        """,
        scope,
    )
    completions = _rows(
        connection,
        f"""
        SELECT rowid AS support_rowid,
               run_id, receipt_id, receipt_sha256, item_id, case_id,
               hearing_id, role, outcome_kind, outcome_id,
               lease_identity_sha256, lease_id, attempt_count,
               retry_generation, backlog_status, backlog_version,
               source_checkpoint_id, source_checkpoint_sha256,
               source_checkpoint_version, resulting_checkpoint_id,
               resulting_checkpoint_sha256, resulting_checkpoint_version,
               completion_case_status, completion_case_revision,
               completion_audit_sequence, completion_audit_entry_hash,
               manifest_id, document_sha256,
               document_sha256 AS body_commitment_sha256,
               typeof(receipt_json) AS support_document_type,
               {completion_size}
        FROM m4_backlog_completion_receipts
        WHERE run_id = ? AND case_id = ?
        ORDER BY item_id, attempt_count, retry_generation, receipt_id
        LIMIT {_LIMIT + 1}
        """,
        scope,
    )
    strict_attempts = _rows(
        connection,
        f"""
        SELECT rowid AS support_rowid,
               run_id, attempt_id, hearing_id, cycle_scope_id,
               cycle_scope_sha256, case_id, role, attempt_index,
               backlog_item_id, retry_generation, request_id, request_sha256,
               response_id, response_content_sha256, parse_receipt_id,
               manifest_id, document_sha256,
               document_sha256 AS body_commitment_sha256,
               typeof(attempt_json) AS support_document_type,
               {attempt_size}
        FROM m4_hearing_strict_parse_failure_attempts
        WHERE run_id = ? AND case_id = ?
        ORDER BY backlog_item_id, retry_generation, attempt_index, attempt_id
        LIMIT {_LIMIT + 1}
        """,
        scope,
    )
    strict_proofs = _rows(
        connection,
        f"""
        SELECT rowid AS support_rowid,
               run_id, proof_id, hearing_id, case_id, source_checkpoint_id,
               source_checkpoint_sha256, source_checkpoint_version,
               backlog_item_id, closure_kind, lease_identity_sha256,
               lease_id, lease_attempt_count, retry_generation, role,
               primary_attempt_id, repair_attempt_id, document_sha256,
               document_sha256 AS body_commitment_sha256,
               typeof(proof_json) AS support_document_type,
               {proof_size}
        FROM m4_hearing_strict_parse_failure_proofs
        WHERE run_id = ? AND case_id = ?
        ORDER BY backlog_item_id, retry_generation, proof_id
        LIMIT {_LIMIT + 1}
        """,
        scope,
    )
    human_reviews = _rows(
        connection,
        f"""
        SELECT rowid AS support_rowid,
               run_id, receipt_id, receipt_sha256, hearing_id, case_id,
               current_pack_id, current_pack_version, judge_cycle, reason,
               source_checkpoint_id, source_checkpoint_sha256,
               source_checkpoint_version, procedural_review_id,
               backlog_item_id, acquisition_model_request_id, manifest_id,
               document_sha256,
               document_sha256 AS body_commitment_sha256,
               typeof(receipt_json) AS support_document_type,
               {human_size}
        FROM m4_hearing_human_review_receipts
        WHERE run_id = ? AND case_id = ?
        ORDER BY hearing_id, judge_cycle, receipt_id
        LIMIT {_LIMIT + 1}
        """,
        scope,
    )
    return _M4BacklogSupportRows(
        items=items,
        versions=versions,
        heads=heads,
        retry_outcomes=retry_outcomes,
        completions=completions,
        strict_attempts=strict_attempts,
        strict_proofs=strict_proofs,
        human_reviews=human_reviews,
    )


@dataclass(frozen=True, slots=True)
class _M4BaseSupportRows:
    run: tuple[sqlite3.Row, ...]
    case_version: tuple[sqlite3.Row, ...]
    audit: tuple[sqlite3.Row, ...]
    case_history: tuple[sqlite3.Row, ...]
    audit_history: tuple[sqlite3.Row, ...]
    packs: tuple[sqlite3.Row, ...]
    screenings: tuple[sqlite3.Row, ...]
    reviews: tuple[sqlite3.Row, ...]


def read_base_support_rows(
    connection: M6LiveReader,
    *,
    run_id: str,
    case_id: str,
    selected_case_revision: int,
    selected_audit_sequence: int,
) -> _M4BaseSupportRows:
    """Read the six body-free base authorities needed by the M4 graph."""

    run = _rows(
        connection,
        """
        SELECT rowid AS support_rowid,
               run_id, manifest_id, revision, audit_head_sequence,
               audit_head_hash, registered_at
        FROM runs
        WHERE run_id = ?
        ORDER BY run_id
        LIMIT 2
        """,
        (run_id,),
        limit=1,
    )
    case_version = _rows(
        connection,
        """
        SELECT rowid AS support_rowid,
               run_id, case_id, revision, status, document_sha256,
               audit_sequence
        FROM case_versions
        WHERE run_id = ? AND case_id = ? AND revision = ?
        ORDER BY revision
        LIMIT 2
        """,
        (run_id, case_id, selected_case_revision),
        limit=1,
    )
    audit = _rows(
        connection,
        """
        SELECT rowid AS support_rowid,
               run_id, sequence, manifest_id, actor, action, object_kind,
               object_id, before_sha256, after_sha256, recorded_at,
               prev_entry_hash, entry_hash, document_sha256
        FROM audit_entries
        WHERE run_id = ? AND sequence = ?
        ORDER BY sequence
        LIMIT 2
        """,
        (run_id, selected_audit_sequence),
        limit=1,
    )
    case_history = _rows(
        connection,
        f"""
        SELECT rowid AS support_rowid,
               run_id, case_id, revision, status, document_sha256,
               audit_sequence
        FROM case_versions
        WHERE run_id = ? AND case_id = ? AND revision <= ?
        ORDER BY revision
        LIMIT {_LIMIT + 1}
        """,
        (run_id, case_id, selected_case_revision),
    )
    audit_history = _rows(
        connection,
        f"""
        SELECT audit.rowid AS support_rowid,
               audit.run_id, audit.sequence, audit.manifest_id, audit.actor,
               audit.action, audit.object_kind, audit.object_id,
               audit.before_sha256, audit.after_sha256, audit.recorded_at,
               audit.prev_entry_hash, audit.entry_hash, audit.document_sha256
        FROM audit_entries AS audit
        JOIN case_versions AS version
          ON version.run_id = audit.run_id
         AND version.audit_sequence = audit.sequence
        WHERE version.run_id = ? AND version.case_id = ?
          AND version.revision <= ?
        ORDER BY version.revision
        LIMIT {_LIMIT + 1}
        """,
        (run_id, case_id, selected_case_revision),
    )
    packs = _rows(
        connection,
        f"""
        SELECT rowid AS support_rowid,
               run_id, pack_id, case_id, manifest_id, version, complete,
               pack_input_sha256, closure_input_sha256, document_sha256,
               created_audit_sequence
        FROM evidence_packs
        WHERE run_id = ? AND case_id = ?
        ORDER BY version, pack_id
        LIMIT {_LIMIT + 1}
        """,
        (run_id, case_id),
    )
    screenings = _rows(
        connection,
        f"""
        SELECT rowid AS support_rowid,
               run_id, screening_id, case_id, version, evidence_pack_id,
               evidence_pack_version, parsed_output_id, decision,
               manifest_id, audit_sequence, document_sha256
        FROM screening_results
        WHERE run_id = ? AND case_id = ?
        ORDER BY version, screening_id
        LIMIT {_LIMIT + 1}
        """,
        (run_id, case_id),
    )
    reviews = _rows(
        connection,
        f"""
        SELECT rowid AS support_rowid,
               run_id, review_id, case_id, version, evidence_pack_id,
               evidence_pack_version, reviewed_verdict_id,
               reviewed_verdict_version, reviewed_verdict_sha256, passed,
               manifest_id, audit_sequence, document_sha256
        FROM procedural_reviews
        WHERE run_id = ? AND case_id = ?
        ORDER BY version, review_id
        LIMIT {_LIMIT + 1}
        """,
        (run_id, case_id),
    )
    return _M4BaseSupportRows(
        run=run,
        case_version=case_version,
        audit=audit,
        case_history=case_history,
        audit_history=audit_history,
        packs=packs,
        screenings=screenings,
        reviews=reviews,
    )
