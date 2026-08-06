"""Bounded, body-free SQLite reads for the M6 M5-precedent plan.

Case-scoped M4 hearings, cycles, and retrieval receipts are fully enumerated
so a later graph builder can select only the membership frozen by the upstream
M4 plan.  M5 physical rows are point-read from exact observation identities.
Historical precedent revisions are enumerated from a bounded run inventory,
then filtered by typed candidate IDs; their referenced embedding rows are read
through the same fixed-ID helper used for observed durable embeddings.

Canonical ``hearing_json``, ``cycle_json``, ``receipt_json``,
``exposure_json``, ``embedding_json``, and ``authority_json`` bodies are never
selected here.  Only their type, byte length, rowid, and stored digest enter
the metadata cut.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from enum import StrEnum
from typing import NoReturn, TypeGuard, cast

from pydantic import ValidationError

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import ArtifactKind
from labcourt.contracts.m6_upgrade_execution_observation import (
    M6UpgradeObservedArtifactIdentity,
)
from labcourt.contracts.m6_upgrade_physical import (
    M6UpgradePhysicalArtifactKind,
    M6UpgradePhysicalArtifactSource,
)
from labcourt.contracts.references import require_reference_token
from labcourt.contracts.storage import ArtifactRef

from ._sqlite_m6_live_read_cut import M6LiveDocumentColumn, M6LiveReader
from ._sqlite_m6_upgrade_m5_precedent_plan import (
    MAX_M6_SQLITE_M5_PRECEDENT_CASE_ROWS,
    MAX_M6_SQLITE_M5_PRECEDENT_DOCUMENT_BYTES,
    MAX_M6_SQLITE_M5_PRECEDENT_EXPOSURES,
    MAX_M6_SQLITE_M5_PRECEDENT_SUPPORT_ROWS,
    M6SQLiteM5PrecedentPlanFailureCode,
    _M6SQLiteM5PrecedentMetadataFailure,
)

_SQLITE_OCTET_LENGTH_MIN_VERSION = (3, 43, 0)
_USE_SQLITE_OCTET_LENGTH = sqlite3.sqlite_version_info >= _SQLITE_OCTET_LENGTH_MIN_VERSION
_CASE_LIMIT = MAX_M6_SQLITE_M5_PRECEDENT_CASE_ROWS
_EXPOSURE_LIMIT = MAX_M6_SQLITE_M5_PRECEDENT_EXPOSURES
_SUPPORT_LIMIT = MAX_M6_SQLITE_M5_PRECEDENT_SUPPORT_ROWS


class M6SQLiteM5PrecedentRowDocumentRoute(StrEnum):
    """Closed document columns whose lengths may be read before bodies."""

    HEARING = "m4_hearings.hearing_json"
    CYCLE = "m4_hearing_cycles.cycle_json"
    RETRIEVAL = "m4_precedent_retrieval_receipts.receipt_json"
    PRECEDENT_EXPOSURE = "m5_precedent_exposures.exposure_json"
    EMBEDDING = "precedent_embeddings.embedding_json"
    PRECEDENT_AUTHORITY = "precedents.authority_json"


_LIVE_DOCUMENT_ROUTE = {
    M6SQLiteM5PrecedentRowDocumentRoute.HEARING: (M6LiveDocumentColumn.M4_HEARING_SESSION_DOCUMENT),
    M6SQLiteM5PrecedentRowDocumentRoute.CYCLE: (M6LiveDocumentColumn.M4_HEARING_CYCLE_DOCUMENT),
    M6SQLiteM5PrecedentRowDocumentRoute.RETRIEVAL: (
        M6LiveDocumentColumn.M4_PRECEDENT_RETRIEVAL_DOCUMENT
    ),
    M6SQLiteM5PrecedentRowDocumentRoute.PRECEDENT_EXPOSURE: (
        M6LiveDocumentColumn.M5_PRECEDENT_EXPOSURE_DOCUMENT
    ),
    M6SQLiteM5PrecedentRowDocumentRoute.EMBEDDING: (
        M6LiveDocumentColumn.M5_PRECEDENT_EMBEDDING_DOCUMENT
    ),
    M6SQLiteM5PrecedentRowDocumentRoute.PRECEDENT_AUTHORITY: (
        M6LiveDocumentColumn.M5_PRECEDENT_AUTHORITY_DOCUMENT
    ),
}
if set(_LIVE_DOCUMENT_ROUTE) != set(M6SQLiteM5PrecedentRowDocumentRoute):
    raise RuntimeError("M6 M5-precedent row document routes must be exhaustive")


def _fail(reason_code: M6SQLiteM5PrecedentPlanFailureCode) -> NoReturn:
    raise _M6SQLiteM5PrecedentMetadataFailure(reason_code)


def _scope(run_id: object, case_id: object | None = None) -> tuple[str, ...]:
    values = (run_id,) if case_id is None else (run_id, case_id)
    if any(type(value) is not str or not value for value in values):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INVALID_ARGUMENT)
    try:
        return tuple(
            require_reference_token(value, "M6 M5-precedent SQLite scope")
            for value in values
            if isinstance(value, str)
        )
    except (TypeError, ValueError):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INVALID_ARGUMENT)


def _is_sha256(value: object) -> TypeGuard[str]:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _ids(
    values: object,
    *,
    limit: int,
    label: str,
    sha256: bool = False,
) -> tuple[str, ...]:
    if type(values) is not tuple or any(type(value) is not str for value in values):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INVALID_ARGUMENT)
    controlled = tuple(values)
    if len(controlled) > limit:
        _fail(M6SQLiteM5PrecedentPlanFailureCode.ROW_LIMIT_EXCEEDED)
    try:
        for value in controlled:
            require_reference_token(value, label)
    except (TypeError, ValueError):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INVALID_ARGUMENT)
    if sha256 and any(not _is_sha256(value) for value in controlled):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INVALID_ARGUMENT)
    if controlled != tuple(sorted(controlled)) or len(controlled) != len(set(controlled)):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INVALID_ARGUMENT)
    return controlled


def _rows(
    connection: M6LiveReader,
    sql: str,
    parameters: tuple[object, ...],
    *,
    limit: int,
) -> tuple[sqlite3.Row, ...]:
    """Fetch one sentinel past a frozen maximum and always close the cursor."""

    try:
        cursor = connection.execute(sql, parameters)
        try:
            rows = tuple(cursor.fetchmany(limit + 1))
        finally:
            cursor.close()
    except sqlite3.Error:
        _fail(M6SQLiteM5PrecedentPlanFailureCode.DATABASE_REJECTED)
    if len(rows) > limit:
        _fail(M6SQLiteM5PrecedentPlanFailureCode.ROW_LIMIT_EXCEEDED)
    return rows


def _row_value(row: sqlite3.Row, column: str) -> object:
    try:
        return row[column]
    except (IndexError, KeyError, TypeError):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)


def _size_projection(column: str) -> str:
    if _USE_SQLITE_OCTET_LENGTH:
        return f"octet_length({column}) AS document_bytes"
    return "NULL AS document_bytes"


def document_bytes(
    connection: M6LiveReader,
    row: sqlite3.Row,
    route: M6SQLiteM5PrecedentRowDocumentRoute,
) -> int:
    """Preflight one exact body length without materializing the body."""

    if type(route) is not M6SQLiteM5PrecedentRowDocumentRoute:
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INVALID_ARGUMENT)
    if _row_value(row, "document_type") != "text":
        _fail(M6SQLiteM5PrecedentPlanFailureCode.DOCUMENT_INVALID)
    rowid = _row_value(row, "document_rowid")
    if type(rowid) is not int or rowid <= 0:
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)
    value = _row_value(row, "document_bytes")
    if not _USE_SQLITE_OCTET_LENGTH:
        value = connection.document_octet_length(_LIVE_DOCUMENT_ROUTE[route], rowid)
    if type(value) is not int or value <= 0:
        _fail(M6SQLiteM5PrecedentPlanFailureCode.DOCUMENT_INVALID)
    if value > MAX_M6_SQLITE_M5_PRECEDENT_DOCUMENT_BYTES:
        _fail(M6SQLiteM5PrecedentPlanFailureCode.DOCUMENT_TOO_LARGE)
    return value


@dataclass(frozen=True, slots=True)
class M6SQLiteM5PrecedentCaseRows:
    """Complete body-free M4 retrieval inventory for one Case."""

    hearings: tuple[sqlite3.Row, ...]
    cycles: tuple[sqlite3.Row, ...]
    retrievals: tuple[sqlite3.Row, ...]


def read_case_retrieval_rows(
    connection: M6LiveReader,
    *,
    run_id: str,
    case_id: str,
) -> M6SQLiteM5PrecedentCaseRows:
    """Fully enumerate normalized M4 retrieval authority for one Case."""

    scope = _scope(run_id, case_id)
    hearing_size = _size_projection("hearing_json")
    cycle_size = _size_projection("cycle_json")
    retrieval_size = _size_projection("receipt_json")
    hearings = _rows(
        connection,
        f"""
        SELECT rowid AS document_rowid,
               run_id, hearing_id, case_id, screening_id, entry_status,
               trigger_review_id, initial_defect_codes_json,
               initial_pack_id, initial_pack_version,
               max_acquisition_rounds, max_rework_rounds,
               max_total_images, max_total_output_tokens, max_judge_cycles,
               hearing_prompt_bundle_sha256,
               prosecutor_model_manifest_id, defender_model_manifest_id,
               judge_model_manifest_id, manifest_id, created_audit_sequence,
               document_sha256, typeof(hearing_json) AS document_type,
               {hearing_size}
        FROM m4_hearings
        WHERE run_id = ? AND case_id = ?
        ORDER BY hearing_id
        LIMIT {_CASE_LIMIT + 1}
        """,
        scope,
        limit=_CASE_LIMIT,
    )
    cycles = _rows(
        connection,
        f"""
        SELECT rowid AS document_rowid,
               run_id, cycle_id, cycle_sha256, hearing_id, case_id,
               cycle_index, prior_acquisition_rounds, prior_rework_rounds,
               cycle_pack_id, cycle_pack_version,
               initial_trigger_review_id, initial_defect_codes_json,
               rework_review_id, rework_defect_codes_json,
               manifest_id, created_audit_sequence,
               typeof(cycle_json) AS document_type, {cycle_size}
        FROM m4_hearing_cycles
        WHERE run_id = ? AND case_id = ?
        ORDER BY hearing_id, cycle_index, cycle_id
        LIMIT {_CASE_LIMIT + 1}
        """,
        scope,
        limit=_CASE_LIMIT,
    )
    retrievals = _rows(
        connection,
        f"""
        SELECT rowid AS document_rowid,
               run_id, retrieval_receipt_id, hearing_id,
               cycle_scope_id, cycle_scope_sha256, case_id,
               prior_acquisition_rounds, prior_rework_rounds,
               current_pack_id, current_pack_version,
               evidence_class, violation_type, rule_version, top_k,
               initial_trigger_review_id, initial_defect_codes_json,
               rework_review_id, rework_defect_codes_json,
               candidate_precedent_refs_json, candidate_snapshot_sha256,
               visible_precedent_refs_json, visible_snapshot_sha256,
               scored_precedents_json, retrieval_status, degraded_reason,
               precedent_retrieval_degraded, retriever_version,
               retriever_manifest_id, query_sha256,
               embedding_model_manifest_id, manifest_id, document_sha256,
               typeof(receipt_json) AS document_type, {retrieval_size}
        FROM m4_precedent_retrieval_receipts
        WHERE run_id = ? AND case_id = ?
        ORDER BY hearing_id, cycle_scope_id, retrieval_receipt_id
        LIMIT {_CASE_LIMIT + 1}
        """,
        scope,
        limit=_CASE_LIMIT,
    )
    return M6SQLiteM5PrecedentCaseRows(
        hearings=hearings,
        cycles=cycles,
        retrievals=retrievals,
    )


_EXPOSURE_SQL = """
SELECT rowid AS document_rowid,
       run_id, exposure_id, exposure_sha256, case_id, hearing_id,
       cycle_index, cycle_scope_id, cycle_scope_sha256,
       retrieval_receipt_id, m4_query_id, m5_query_id, m5_result_id,
       candidate_count, exposed_count, policy_id, bridge_manifest_id,
       manifest_id, document_sha256,
       typeof(exposure_json) AS document_type,
       {size_projection}
FROM m5_precedent_exposures
WHERE run_id = ? AND exposure_id = ?
ORDER BY exposure_id
LIMIT 2
"""

_EMBEDDING_SQL = """
SELECT rowid AS document_rowid,
       run_id, embedding_id, request_id, channel, input_ref, input_sha256,
       model_manifest_id, dimensions, algorithm, manifest_id,
       document_sha256, typeof(embedding_json) AS document_type,
       {size_projection}
FROM precedent_embeddings
WHERE run_id = ? AND embedding_id = ?
ORDER BY embedding_id
LIMIT 2
"""


def _point_rows(
    connection: M6LiveReader,
    *,
    run_id: str,
    artifact_ids: tuple[str, ...],
    sql: str,
    body_column: str,
) -> tuple[sqlite3.Row, ...]:
    rows: list[sqlite3.Row] = []
    statement = sql.format(size_projection=_size_projection(body_column))
    for artifact_id in artifact_ids:
        matched = _rows(
            connection,
            statement,
            (run_id, artifact_id),
            limit=1,
        )
        if len(matched) != 1:
            _fail(M6SQLiteM5PrecedentPlanFailureCode.SCOPE_NOT_FOUND)
        rows.extend(matched)
    return tuple(rows)


def read_exposure_rows(
    connection: M6LiveReader,
    *,
    run_id: str,
    exposure_ids: tuple[str, ...],
) -> tuple[sqlite3.Row, ...]:
    """Point-read exactly the exposure IDs supplied by typed observations."""

    (controlled_run_id,) = _scope(run_id)
    controlled_ids = _ids(
        exposure_ids,
        limit=_EXPOSURE_LIMIT,
        label="M6 observed exposure_id",
        sha256=True,
    )
    return _point_rows(
        connection,
        run_id=controlled_run_id,
        artifact_ids=controlled_ids,
        sql=_EXPOSURE_SQL,
        body_column="exposure_json",
    )


def read_durable_embedding_rows(
    connection: M6LiveReader,
    *,
    run_id: str,
    embedding_ids: tuple[str, ...],
) -> tuple[sqlite3.Row, ...]:
    """Point-read observed or support embedding IDs through fixed literal SQL."""

    (controlled_run_id,) = _scope(run_id)
    controlled_ids = _ids(
        embedding_ids,
        limit=_SUPPORT_LIMIT,
        label="M6 durable embedding_id",
        sha256=True,
    )
    return _point_rows(
        connection,
        run_id=controlled_run_id,
        artifact_ids=controlled_ids,
        sql=_EMBEDDING_SQL,
        body_column="embedding_json",
    )


@dataclass(frozen=True, slots=True)
class M6SQLiteM5PrecedentObservedRows:
    exposures: tuple[sqlite3.Row, ...]
    durable_embeddings: tuple[sqlite3.Row, ...]


def read_observed_artifact_rows(
    connection: M6LiveReader,
    *,
    run_id: str,
    observations: tuple[M6UpgradeObservedArtifactIdentity, ...],
    derived_query_embedding_ids: tuple[str, ...],
) -> M6SQLiteM5PrecedentObservedRows:
    """Read observed durable rows while excluding typed derived query IDs."""

    if type(observations) is not tuple or any(
        type(value) is not M6UpgradeObservedArtifactIdentity for value in observations
    ):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INVALID_ARGUMENT)
    if any(
        value.source != M6UpgradePhysicalArtifactSource.M5_PRECEDENT
        or value.kind
        not in {
            M6UpgradePhysicalArtifactKind.PRECEDENT_EXPOSURE,
            M6UpgradePhysicalArtifactKind.EMBEDDING,
        }
        for value in observations
    ):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INVALID_ARGUMENT)
    keys = tuple(value.identity_key for value in observations)
    if len(keys) != len(set(keys)) or observations != tuple(
        sorted(observations, key=lambda value: value.sort_key)
    ):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INVALID_ARGUMENT)
    derived = _ids(
        derived_query_embedding_ids,
        limit=_SUPPORT_LIMIT,
        label="M6 derived query embedding_id",
        sha256=True,
    )
    exposure_ids = tuple(
        value.artifact_id
        for value in observations
        if value.kind == M6UpgradePhysicalArtifactKind.PRECEDENT_EXPOSURE
    )
    observed_embedding_ids = {
        value.artifact_id
        for value in observations
        if value.kind == M6UpgradePhysicalArtifactKind.EMBEDDING
    }
    if not set(derived).issubset(observed_embedding_ids):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INVENTORY_MISMATCH)
    durable_ids = tuple(sorted(observed_embedding_ids - set(derived)))
    return M6SQLiteM5PrecedentObservedRows(
        exposures=read_exposure_rows(
            connection,
            run_id=run_id,
            exposure_ids=exposure_ids,
        ),
        durable_embeddings=read_durable_embedding_rows(
            connection,
            run_id=run_id,
            embedding_ids=durable_ids,
        ),
    )


def _json_array(row: sqlite3.Row, column: str) -> list[object]:
    raw = _row_value(row, column)
    if type(raw) is not str:
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)
    try:
        decoded = json.loads(raw)
    except (TypeError, ValueError, json.JSONDecodeError):
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)
    if type(decoded) is not list:
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)
    return decoded


def normalized_json_sha256(row: sqlite3.Row, column: str) -> str:
    """Hash one normalized JSON metadata column after strict JSON decoding."""

    decoded = _json_array(row, column)
    return hashlib.sha256(canonical_json(decoded).encode("utf-8")).hexdigest()


def candidate_precedent_ids(
    retrieval_rows: tuple[sqlite3.Row, ...],
) -> tuple[str, ...]:
    """Return the exact stable candidate precedent-ID union from normalized refs."""

    if type(retrieval_rows) is not tuple:
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INVALID_ARGUMENT)
    candidate_ids: set[str] = set()
    for row in retrieval_rows:
        decoded = _json_array(row, "candidate_precedent_refs_json")
        current: list[str] = []
        for payload in decoded:
            try:
                reference = ArtifactRef.model_validate(payload)
            except (TypeError, ValueError, ValidationError):
                _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)
            if reference.kind != ArtifactKind.PRECEDENT:
                _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)
            current.append(reference.artifact_id)
        if current != sorted(current) or len(current) != len(set(current)):
            _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)
        candidate_ids.update(current)
    if len(candidate_ids) > _SUPPORT_LIMIT:
        _fail(M6SQLiteM5PrecedentPlanFailureCode.ROW_LIMIT_EXCEEDED)
    return tuple(sorted(candidate_ids))


def read_candidate_precedent_revision_rows(
    connection: M6LiveReader,
    *,
    run_id: str,
    precedent_ids: tuple[str, ...],
) -> tuple[sqlite3.Row, ...]:
    """Enumerate every revision of each exact candidate through fixed range SQL."""

    (controlled_run_id,) = _scope(run_id)
    controlled_ids = _ids(
        precedent_ids,
        limit=_SUPPORT_LIMIT,
        label="M6 candidate precedent_id",
    )
    if not controlled_ids:
        return ()
    authority_size = _size_projection("authority_json")
    statement = f"""
        SELECT rowid AS document_rowid,
               run_id, precedent_id, revision, authority_id, status, source,
               evidence_class, violation_type, decision_direction,
               rule_version, source_case_id, citation_count,
               text_embedding_id, visual_embedding_ids_json,
               created_at, activation_not_before, activated_at,
               manifest_id, document_sha256,
               typeof(authority_json) AS document_type, {authority_size}
        FROM precedents
        WHERE run_id = ? AND precedent_id = ?
        ORDER BY revision
        LIMIT {_SUPPORT_LIMIT + 1}
        """
    selected: list[sqlite3.Row] = []
    for precedent_id in controlled_ids:
        revisions = _rows(
            connection,
            statement,
            (controlled_run_id, precedent_id),
            limit=_SUPPORT_LIMIT,
        )
        if not revisions:
            _fail(M6SQLiteM5PrecedentPlanFailureCode.SCOPE_NOT_FOUND)
        selected.extend(revisions)
        if len(selected) > _SUPPORT_LIMIT:
            _fail(M6SQLiteM5PrecedentPlanFailureCode.ROW_LIMIT_EXCEEDED)
    return tuple(selected)


def precedent_revision_embedding_ids(
    precedent_rows: tuple[sqlite3.Row, ...],
) -> tuple[str, ...]:
    """Return every durable embedding ID named by normalized precedent indexes."""

    if type(precedent_rows) is not tuple:
        _fail(M6SQLiteM5PrecedentPlanFailureCode.INVALID_ARGUMENT)
    embedding_ids: set[str] = set()
    for row in precedent_rows:
        text_id = _row_value(row, "text_embedding_id")
        if text_id is not None:
            if not _is_sha256(text_id):
                _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)
            try:
                require_reference_token(text_id, "precedent text embedding_id")
            except (TypeError, ValueError):
                _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)
            embedding_ids.add(text_id)
        decoded = _json_array(row, "visual_embedding_ids_json")
        if any(not _is_sha256(value) for value in decoded):
            _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)
        visual = cast(tuple[str, ...], tuple(decoded))
        try:
            for value in visual:
                require_reference_token(value, "precedent visual embedding_id")
        except (TypeError, ValueError):
            _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)
        if visual != tuple(sorted(visual)) or len(visual) != len(set(visual)):
            _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)
        if text_id is not None and text_id in visual:
            _fail(M6SQLiteM5PrecedentPlanFailureCode.INDEX_BINDING_MISMATCH)
        embedding_ids.update(visual)
    if len(embedding_ids) > _SUPPORT_LIMIT:
        _fail(M6SQLiteM5PrecedentPlanFailureCode.ROW_LIMIT_EXCEEDED)
    return tuple(sorted(embedding_ids))


__all__ = [
    "M6SQLiteM5PrecedentCaseRows",
    "M6SQLiteM5PrecedentObservedRows",
    "M6SQLiteM5PrecedentRowDocumentRoute",
    "candidate_precedent_ids",
    "document_bytes",
    "normalized_json_sha256",
    "precedent_revision_embedding_ids",
    "read_candidate_precedent_revision_rows",
    "read_case_retrieval_rows",
    "read_durable_embedding_rows",
    "read_exposure_rows",
    "read_observed_artifact_rows",
]
