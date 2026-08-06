"""Bounded, body-free SQLite reads for M6 acquisition metadata planning.

The six acquisition authority tables are always enumerated by the selected
``run_id`` and ``case_id``.  Observation identities never enter these queries.
Relational evidence outputs are the narrower exception: their exact primary
keys come only from typed, selected-Case ``ToolResult.output_refs`` and are
looked up through three fixed literal statements.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from enum import StrEnum
from typing import NoReturn

from labcourt.contracts.enums import ArtifactKind
from labcourt.contracts.evidence import ToolResult

from ._sqlite_m6_live_read_cut import M6LiveDocumentColumn, M6LiveReader
from ._sqlite_m6_upgrade_acquisition_plan import (
    MAX_M6_SQLITE_ACQUISITION_DOCUMENT_BYTES,
    MAX_M6_SQLITE_ACQUISITION_ITEMS,
    MAX_M6_SQLITE_ACQUISITION_SELECTED_PACKS,
    MAX_M6_SQLITE_ACQUISITION_SUPPORT_ROWS_PER_ROUTE,
    M6SQLiteAcquisitionPlanFailureCode,
    _M6SQLiteAcquisitionMetadataFailure,
)

_SQLITE_OCTET_LENGTH_MIN_VERSION = (3, 43, 0)
_USE_SQLITE_OCTET_LENGTH = sqlite3.sqlite_version_info >= _SQLITE_OCTET_LENGTH_MIN_VERSION
_PRIMARY_LIMIT = MAX_M6_SQLITE_ACQUISITION_ITEMS
_PACK_LIMIT = MAX_M6_SQLITE_ACQUISITION_SELECTED_PACKS
_SUPPORT_LIMIT = MAX_M6_SQLITE_ACQUISITION_SUPPORT_ROWS_PER_ROUTE


class M6SQLiteAcquisitionRowDocumentRoute(StrEnum):
    """Closed document columns whose lengths may be read before their bodies."""

    ACQUISITION_REQUEST = "m4_acquisition_requests.request_json"
    ACQUISITION_CLAIM_REQUEST = "m4_acquisition_execution_claims.request_json"
    ACQUISITION_CLAIM = "m4_acquisition_execution_claims.claim_json"
    TOOL_EXECUTION_MANIFEST = "m4_tool_execution_manifests.manifest_json"
    EXECUTION_PUBLICATION = "m4_acquisition_execution_publications.publication_json"
    TOOL_EXECUTION_RECEIPT = "m4_tool_execution_receipts.receipt_json"
    EVIDENCE_PACK_DERIVATION = "m4_evidence_pack_derivations.derivation_json"
    SELECTED_EVIDENCE_PACK = "evidence_packs.pack_json"
    HEARING_CHECKPOINT = "m4_hearing_checkpoints.checkpoint_json"
    HEARING_ROUND = "m4_hearing_rounds.round_json"
    CASE_VERSION = "case_versions.case_json"
    AUDIT_ENTRY = "audit_entries.entry_json"


_LIVE_DOCUMENT_ROUTE = {
    M6SQLiteAcquisitionRowDocumentRoute.ACQUISITION_REQUEST: (
        M6LiveDocumentColumn.M4_ACQUISITION_REQUEST_DOCUMENT
    ),
    M6SQLiteAcquisitionRowDocumentRoute.ACQUISITION_CLAIM_REQUEST: (
        M6LiveDocumentColumn.M4_ACQUISITION_CLAIM_REQUEST_DOCUMENT
    ),
    M6SQLiteAcquisitionRowDocumentRoute.ACQUISITION_CLAIM: (
        M6LiveDocumentColumn.M4_ACQUISITION_CLAIM_DOCUMENT
    ),
    M6SQLiteAcquisitionRowDocumentRoute.TOOL_EXECUTION_MANIFEST: (
        M6LiveDocumentColumn.M4_TOOL_EXECUTION_MANIFEST_DOCUMENT
    ),
    M6SQLiteAcquisitionRowDocumentRoute.EXECUTION_PUBLICATION: (
        M6LiveDocumentColumn.M4_ACQUISITION_PUBLICATION_DOCUMENT
    ),
    M6SQLiteAcquisitionRowDocumentRoute.TOOL_EXECUTION_RECEIPT: (
        M6LiveDocumentColumn.M4_TOOL_EXECUTION_RECEIPT_DOCUMENT
    ),
    M6SQLiteAcquisitionRowDocumentRoute.EVIDENCE_PACK_DERIVATION: (
        M6LiveDocumentColumn.M4_EVIDENCE_PACK_DERIVATION_DOCUMENT
    ),
    M6SQLiteAcquisitionRowDocumentRoute.SELECTED_EVIDENCE_PACK: (
        M6LiveDocumentColumn.EVIDENCE_PACK_DOCUMENT
    ),
    M6SQLiteAcquisitionRowDocumentRoute.HEARING_CHECKPOINT: (
        M6LiveDocumentColumn.M4_HEARING_CHECKPOINT_DOCUMENT
    ),
    M6SQLiteAcquisitionRowDocumentRoute.HEARING_ROUND: (
        M6LiveDocumentColumn.M4_HEARING_ROUND_DOCUMENT
    ),
    M6SQLiteAcquisitionRowDocumentRoute.CASE_VERSION: (M6LiveDocumentColumn.CASE_VERSION_DOCUMENT),
    M6SQLiteAcquisitionRowDocumentRoute.AUDIT_ENTRY: (M6LiveDocumentColumn.AUDIT_ENTRY_DOCUMENT),
}
_DOCUMENT_METADATA = {
    M6SQLiteAcquisitionRowDocumentRoute.ACQUISITION_REQUEST: (
        "document_rowid",
        "request_document_type",
        "request_document_bytes",
    ),
    M6SQLiteAcquisitionRowDocumentRoute.ACQUISITION_CLAIM_REQUEST: (
        "document_rowid",
        "claim_request_document_type",
        "claim_request_document_bytes",
    ),
    M6SQLiteAcquisitionRowDocumentRoute.ACQUISITION_CLAIM: (
        "document_rowid",
        "claim_document_type",
        "claim_document_bytes",
    ),
    M6SQLiteAcquisitionRowDocumentRoute.TOOL_EXECUTION_MANIFEST: (
        "document_rowid",
        "manifest_document_type",
        "manifest_document_bytes",
    ),
    M6SQLiteAcquisitionRowDocumentRoute.EXECUTION_PUBLICATION: (
        "document_rowid",
        "publication_document_type",
        "publication_document_bytes",
    ),
    M6SQLiteAcquisitionRowDocumentRoute.TOOL_EXECUTION_RECEIPT: (
        "document_rowid",
        "receipt_document_type",
        "receipt_document_bytes",
    ),
    M6SQLiteAcquisitionRowDocumentRoute.EVIDENCE_PACK_DERIVATION: (
        "document_rowid",
        "derivation_document_type",
        "derivation_document_bytes",
    ),
    M6SQLiteAcquisitionRowDocumentRoute.SELECTED_EVIDENCE_PACK: (
        "document_rowid",
        "pack_document_type",
        "pack_document_bytes",
    ),
    M6SQLiteAcquisitionRowDocumentRoute.HEARING_CHECKPOINT: (
        "support_rowid",
        "support_document_type",
        "support_document_bytes",
    ),
    M6SQLiteAcquisitionRowDocumentRoute.HEARING_ROUND: (
        "support_rowid",
        "support_document_type",
        "support_document_bytes",
    ),
    M6SQLiteAcquisitionRowDocumentRoute.CASE_VERSION: (
        "support_rowid",
        "support_document_type",
        "support_document_bytes",
    ),
    M6SQLiteAcquisitionRowDocumentRoute.AUDIT_ENTRY: (
        "support_rowid",
        "support_document_type",
        "support_document_bytes",
    ),
}

if set(_LIVE_DOCUMENT_ROUTE) != set(M6SQLiteAcquisitionRowDocumentRoute) or set(
    _DOCUMENT_METADATA
) != set(M6SQLiteAcquisitionRowDocumentRoute):
    raise RuntimeError("M6 acquisition row document routes must be exhaustive")


def _fail(reason_code: M6SQLiteAcquisitionPlanFailureCode) -> NoReturn:
    raise _M6SQLiteAcquisitionMetadataFailure(reason_code)


def _scope(run_id: object, case_id: object) -> tuple[str, str]:
    if type(run_id) is not str or not run_id or type(case_id) is not str or not case_id:
        _fail(M6SQLiteAcquisitionPlanFailureCode.INVALID_ARGUMENT)
    return run_id, case_id


def _rows(
    connection: M6LiveReader,
    sql: str,
    parameters: tuple[object, ...],
    *,
    limit: int,
) -> tuple[sqlite3.Row, ...]:
    """Fetch no more than one sentinel row past an already-frozen limit."""

    try:
        cursor = connection.execute(sql, parameters)
        try:
            rows = tuple(cursor.fetchmany(limit + 1))
        finally:
            cursor.close()
    except sqlite3.Error:
        _fail(M6SQLiteAcquisitionPlanFailureCode.DATABASE_REJECTED)
    if len(rows) > limit:
        _fail(M6SQLiteAcquisitionPlanFailureCode.ROW_LIMIT_EXCEEDED)
    return rows


def _size_projection(column: str, alias: str) -> str:
    if _USE_SQLITE_OCTET_LENGTH:
        return f"octet_length({column}) AS {alias}"
    return f"NULL AS {alias}"


def _row_value(row: sqlite3.Row, column: str) -> object:
    try:
        return row[column]
    except (IndexError, KeyError, TypeError):
        _fail(M6SQLiteAcquisitionPlanFailureCode.INDEX_BINDING_MISMATCH)


def document_bytes(
    connection: M6LiveReader,
    row: sqlite3.Row,
    route: M6SQLiteAcquisitionRowDocumentRoute,
) -> int:
    """Preflight one exact document length without materializing its body."""

    if type(route) is not M6SQLiteAcquisitionRowDocumentRoute:
        _fail(M6SQLiteAcquisitionPlanFailureCode.INVALID_ARGUMENT)
    rowid_alias, type_alias, size_alias = _DOCUMENT_METADATA[route]
    if _row_value(row, type_alias) != "text":
        _fail(M6SQLiteAcquisitionPlanFailureCode.DOCUMENT_INVALID)
    rowid = _row_value(row, rowid_alias)
    if type(rowid) is not int or rowid <= 0:
        _fail(M6SQLiteAcquisitionPlanFailureCode.INDEX_BINDING_MISMATCH)
    value = _row_value(row, size_alias)
    if not _USE_SQLITE_OCTET_LENGTH:
        value = connection.document_octet_length(_LIVE_DOCUMENT_ROUTE[route], rowid)
    if type(value) is not int or value <= 0:
        _fail(M6SQLiteAcquisitionPlanFailureCode.DOCUMENT_INVALID)
    if value > MAX_M6_SQLITE_ACQUISITION_DOCUMENT_BYTES:
        _fail(M6SQLiteAcquisitionPlanFailureCode.DOCUMENT_TOO_LARGE)
    return value


@dataclass(frozen=True, slots=True)
class M6SQLiteAcquisitionPrimaryRows:
    requests: tuple[sqlite3.Row, ...]
    claims: tuple[sqlite3.Row, ...]
    manifests: tuple[sqlite3.Row, ...]
    publications: tuple[sqlite3.Row, ...]
    receipts: tuple[sqlite3.Row, ...]
    derivations: tuple[sqlite3.Row, ...]
    packs: tuple[sqlite3.Row, ...]


def read_primary_rows(
    connection: M6LiveReader,
    *,
    run_id: str,
    case_id: str,
) -> M6SQLiteAcquisitionPrimaryRows:
    """Fully enumerate six Case-scoped acquisition tables and pack metadata."""

    scope = _scope(run_id, case_id)
    request_size = _size_projection("request_json", "request_document_bytes")
    claim_request_size = _size_projection(
        "request_json",
        "claim_request_document_bytes",
    )
    claim_size = _size_projection("claim_json", "claim_document_bytes")
    manifest_size = _size_projection("manifest_json", "manifest_document_bytes")
    publication_size = _size_projection("publication_json", "publication_document_bytes")
    receipt_size = _size_projection("receipt_json", "receipt_document_bytes")
    derivation_size = _size_projection("derivation_json", "derivation_document_bytes")
    pack_size = _size_projection("pack_json", "pack_document_bytes")

    requests = _rows(
        connection,
        f"""
        SELECT rowid AS document_rowid,
               run_id, acquisition_request_id, hearing_id, cycle_scope_id,
               cycle_scope_sha256, case_id, round_index,
               prior_acquisition_rounds, prior_rework_rounds,
               evidence_pack_id, evidence_pack_version, judge_output_id,
               source_model_request_id, source_model_response_id, action,
               validated_parameters_sha256, manifest_id, document_sha256,
               typeof(request_json) AS request_document_type,
               {request_size}
        FROM m4_acquisition_requests
        WHERE run_id = ? AND case_id = ?
        ORDER BY acquisition_request_id
        LIMIT {_PRIMARY_LIMIT + 1}
        """,
        scope,
        limit=_PRIMARY_LIMIT,
    )
    claims = _rows(
        connection,
        f"""
        SELECT rowid AS document_rowid,
               run_id, acquisition_request_id, request_document_sha256,
               case_id, hearing_id, execution_mode, idempotency_key, status,
               owner_token_sha256, owner_fence, lease_expires_at,
               execution_publication_id, created_at, updated_at,
               document_sha256,
               typeof(request_json) AS claim_request_document_type,
               {claim_request_size},
               typeof(claim_json) AS claim_document_type,
               {claim_size}
        FROM m4_acquisition_execution_claims
        WHERE run_id = ? AND case_id = ?
        ORDER BY acquisition_request_id
        LIMIT {_PRIMARY_LIMIT + 1}
        """,
        scope,
        limit=_PRIMARY_LIMIT,
    )
    manifests = _rows(
        connection,
        f"""
        SELECT rowid AS document_rowid,
               run_id, execution_manifest_id, case_id, hearing_id,
               acquisition_request_id, action, tool_id, tool_revision,
               parameters_schema_sha256, component_manifest_id,
               model_manifest_id, manifest_id, document_sha256,
               typeof(manifest_json) AS manifest_document_type,
               {manifest_size}
        FROM m4_tool_execution_manifests
        WHERE run_id = ? AND case_id = ?
        ORDER BY acquisition_request_id, execution_manifest_id
        LIMIT {_PRIMARY_LIMIT + 1}
        """,
        scope,
        limit=_PRIMARY_LIMIT,
    )
    publications = _rows(
        connection,
        f"""
        SELECT rowid AS document_rowid,
               run_id, execution_publication_id, acquisition_request_id,
               request_document_sha256, case_id, hearing_id,
               execution_manifest_id, tool_result_id, execution_mode,
               idempotency_key, claim_owner_sha256, claim_fence,
               document_sha256,
               typeof(publication_json) AS publication_document_type,
               {publication_size}
        FROM m4_acquisition_execution_publications
        WHERE run_id = ? AND case_id = ?
        ORDER BY acquisition_request_id, execution_publication_id
        LIMIT {_PRIMARY_LIMIT + 1}
        """,
        scope,
        limit=_PRIMARY_LIMIT,
    )
    receipts = _rows(
        connection,
        f"""
        SELECT rowid AS document_rowid,
               run_id, receipt_id, acquisition_request_id, hearing_id,
               cycle_scope_id, cycle_scope_sha256, case_id, action,
               execution_manifest_id, tool_result_id, resulting_pack_id,
               resulting_pack_version, document_sha256,
               typeof(receipt_json) AS receipt_document_type,
               {receipt_size}
        FROM m4_tool_execution_receipts
        WHERE run_id = ? AND case_id = ?
        ORDER BY acquisition_request_id, receipt_id
        LIMIT {_PRIMARY_LIMIT + 1}
        """,
        scope,
        limit=_PRIMARY_LIMIT,
    )
    derivations = _rows(
        connection,
        f"""
        SELECT rowid AS document_rowid,
               run_id, derivation_id, hearing_id, source_cycle_scope_id,
               source_cycle_scope_sha256, case_id, previous_pack_id,
               previous_pack_version, new_pack_id, new_pack_version,
               tool_receipt_id, manifest_id, document_sha256,
               typeof(derivation_json) AS derivation_document_type,
               {derivation_size}
        FROM m4_evidence_pack_derivations
        WHERE run_id = ? AND case_id = ?
        ORDER BY new_pack_version, new_pack_id, derivation_id
        LIMIT {_PRIMARY_LIMIT + 1}
        """,
        scope,
        limit=_PRIMARY_LIMIT,
    )
    packs = _rows(
        connection,
        f"""
        SELECT rowid AS document_rowid,
               run_id, pack_id, case_id, manifest_id, version, complete,
               pack_input_sha256, closure_input_sha256, document_sha256,
               created_audit_sequence,
               typeof(pack_json) AS pack_document_type,
               {pack_size}
        FROM evidence_packs
        WHERE run_id = ? AND case_id = ?
        ORDER BY version, pack_id
        LIMIT {_PACK_LIMIT + 1}
        """,
        scope,
        limit=_PACK_LIMIT,
    )
    return M6SQLiteAcquisitionPrimaryRows(
        requests=requests,
        claims=claims,
        manifests=manifests,
        publications=publications,
        receipts=receipts,
        derivations=derivations,
        packs=packs,
    )


@dataclass(frozen=True, slots=True)
class M6SQLiteAcquisitionHearingSupportRows:
    checkpoints: tuple[sqlite3.Row, ...]
    rounds: tuple[sqlite3.Row, ...]


def read_hearing_support_rows(
    connection: M6LiveReader,
    *,
    run_id: str,
    case_id: str,
) -> M6SQLiteAcquisitionHearingSupportRows:
    """Enumerate every Case-scoped checkpoint and optional committed round."""

    scope = _scope(run_id, case_id)
    checkpoint_size = _size_projection("checkpoint_json", "support_document_bytes")
    round_size = _size_projection("round_json", "support_document_bytes")
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
        LIMIT {_SUPPORT_LIMIT + 1}
        """,
        scope,
        limit=_SUPPORT_LIMIT,
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
        LIMIT {_SUPPORT_LIMIT + 1}
        """,
        scope,
        limit=_SUPPORT_LIMIT,
    )
    return M6SQLiteAcquisitionHearingSupportRows(
        checkpoints=checkpoints,
        rounds=rounds,
    )


@dataclass(frozen=True, slots=True)
class M6SQLiteAcquisitionTransitionSupportRows:
    case_versions: tuple[sqlite3.Row, ...]
    audits: tuple[sqlite3.Row, ...]


def read_transition_support_rows(
    connection: M6LiveReader,
    *,
    run_id: str,
    case_id: str,
    selected_case_revision: int,
) -> M6SQLiteAcquisitionTransitionSupportRows:
    """Enumerate Case/audit transition metadata through the selected cut."""

    scope = _scope(run_id, case_id)
    if type(selected_case_revision) is not int or selected_case_revision <= 0:
        _fail(M6SQLiteAcquisitionPlanFailureCode.INVALID_ARGUMENT)
    case_size = _size_projection("version.case_json", "support_document_bytes")
    audit_size = _size_projection("audit.entry_json", "support_document_bytes")
    parameters = (*scope, selected_case_revision)
    case_versions = _rows(
        connection,
        f"""
        SELECT version.rowid AS support_rowid,
               version.run_id, version.case_id, version.revision,
               version.status, version.document_sha256,
               version.audit_sequence,
               version.document_sha256 AS body_commitment_sha256,
               typeof(version.case_json) AS support_document_type,
               {case_size}
        FROM case_versions AS version
        WHERE version.run_id = ? AND version.case_id = ?
          AND version.revision <= ?
        ORDER BY version.revision
        LIMIT {_SUPPORT_LIMIT + 1}
        """,
        parameters,
        limit=_SUPPORT_LIMIT,
    )
    audits = _rows(
        connection,
        f"""
        SELECT audit.rowid AS support_rowid,
               audit.run_id, audit.sequence, audit.manifest_id, audit.actor,
               audit.action, audit.object_kind, audit.object_id,
               audit.before_sha256, audit.after_sha256, audit.recorded_at,
               audit.prev_entry_hash, audit.entry_hash,
               audit.document_sha256,
               audit.document_sha256 AS body_commitment_sha256,
               typeof(audit.entry_json) AS support_document_type,
               {audit_size}
        FROM audit_entries AS audit
        JOIN case_versions AS version
          ON version.run_id = audit.run_id
         AND version.audit_sequence = audit.sequence
        WHERE version.run_id = ? AND version.case_id = ?
          AND version.revision <= ?
        ORDER BY version.revision, audit.sequence
        LIMIT {_SUPPORT_LIMIT + 1}
        """,
        parameters,
        limit=_SUPPORT_LIMIT,
    )
    return M6SQLiteAcquisitionTransitionSupportRows(
        case_versions=case_versions,
        audits=audits,
    )


@dataclass(frozen=True, slots=True)
class M6SQLiteAcquisitionOutputSupportRows:
    frames: tuple[sqlite3.Row, ...]
    detections: tuple[sqlite3.Row, ...]
    crops: tuple[sqlite3.Row, ...]


_FRAME_OUTPUT_SQL = """
SELECT rowid AS support_rowid,
       run_id, frame_id, manifest_id, camera_id, stream_id, frame_index,
       fps_num, fps_den, width, height, content_sha256, document_sha256
FROM frames
WHERE run_id = ? AND frame_id = ?
ORDER BY frame_id
LIMIT 2
"""
_DETECTION_OUTPUT_SQL = """
SELECT rowid AS support_rowid,
       run_id, detection_id, frame_id, manifest_id, detector_manifest_id,
       label, document_sha256, registered_at
FROM detections
WHERE run_id = ? AND detection_id = ?
ORDER BY detection_id
LIMIT 2
"""
_CROP_OUTPUT_SQL = """
SELECT rowid AS support_rowid,
       run_id, crop_id, case_id, hearing_id, acquisition_request_id,
       execution_manifest_id, frame_id, media_sha256, source_media_sha256,
       pixel_sha256, source_pack_id, source_pack_version, manifest_id,
       document_sha256
FROM m4_acquired_crops
WHERE run_id = ? AND case_id = ? AND crop_id = ?
ORDER BY crop_id
LIMIT 2
"""


def _selected_output_ids(
    selected_case_tool_results: tuple[ToolResult, ...],
) -> dict[ArtifactKind, tuple[str, ...]]:
    if type(selected_case_tool_results) is not tuple or any(
        type(result) is not ToolResult for result in selected_case_tool_results
    ):
        _fail(M6SQLiteAcquisitionPlanFailureCode.INVALID_ARGUMENT)
    by_result: dict[str, ToolResult] = {}
    for result in selected_case_tool_results:
        existing = by_result.get(result.tool_result_id)
        if existing is not None and existing != result:
            _fail(M6SQLiteAcquisitionPlanFailureCode.INVENTORY_MISMATCH)
        by_result[result.tool_result_id] = result
    if len(by_result) > _PRIMARY_LIMIT:
        _fail(M6SQLiteAcquisitionPlanFailureCode.ROW_LIMIT_EXCEEDED)

    ids: dict[ArtifactKind, set[str]] = {
        ArtifactKind.FRAME: set(),
        ArtifactKind.DETECTION: set(),
        ArtifactKind.CROP: set(),
    }
    for result in by_result.values():
        for ref in result.output_refs:
            if ref.kind == ArtifactKind.OBJECTIVE_FACT:
                # The typed selected EvidencePack is the authority for facts;
                # there is deliberately no independent objective-fact table.
                continue
            route_ids = ids.get(ref.kind)
            if route_ids is None:
                _fail(M6SQLiteAcquisitionPlanFailureCode.INVENTORY_MISMATCH)
            route_ids.add(ref.artifact_id)
    total = sum(len(values) for values in ids.values())
    if total > _SUPPORT_LIMIT or any(len(values) > _SUPPORT_LIMIT for values in ids.values()):
        _fail(M6SQLiteAcquisitionPlanFailureCode.ROW_LIMIT_EXCEEDED)
    return {kind: tuple(sorted(values)) for kind, values in ids.items()}


def read_selected_tool_result_output_rows(
    connection: M6LiveReader,
    *,
    run_id: str,
    case_id: str,
    selected_case_tool_results: tuple[ToolResult, ...],
) -> M6SQLiteAcquisitionOutputSupportRows:
    """Look up only typed selected-Case ToolResult output identities."""

    controlled_run_id, controlled_case_id = _scope(run_id, case_id)
    ids = _selected_output_ids(selected_case_tool_results)
    frames = tuple(
        row
        for artifact_id in ids[ArtifactKind.FRAME]
        for row in _rows(
            connection,
            _FRAME_OUTPUT_SQL,
            (controlled_run_id, artifact_id),
            limit=1,
        )
    )
    detections = tuple(
        row
        for artifact_id in ids[ArtifactKind.DETECTION]
        for row in _rows(
            connection,
            _DETECTION_OUTPUT_SQL,
            (controlled_run_id, artifact_id),
            limit=1,
        )
    )
    crops = tuple(
        row
        for artifact_id in ids[ArtifactKind.CROP]
        for row in _rows(
            connection,
            _CROP_OUTPUT_SQL,
            (controlled_run_id, controlled_case_id, artifact_id),
            limit=1,
        )
    )
    return M6SQLiteAcquisitionOutputSupportRows(
        frames=frames,
        detections=detections,
        crops=crops,
    )


__all__ = [
    "M6SQLiteAcquisitionHearingSupportRows",
    "M6SQLiteAcquisitionOutputSupportRows",
    "M6SQLiteAcquisitionPrimaryRows",
    "M6SQLiteAcquisitionRowDocumentRoute",
    "M6SQLiteAcquisitionTransitionSupportRows",
    "document_bytes",
    "read_hearing_support_rows",
    "read_primary_rows",
    "read_selected_tool_result_output_rows",
    "read_transition_support_rows",
]
