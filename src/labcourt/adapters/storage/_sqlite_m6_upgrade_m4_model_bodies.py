"""Strict same-snapshot decoding for a frozen M4 model-document plan."""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass
from typing import cast

from pydantic import BaseModel, ValidationError

from labcourt.application.m6_hearing_model_call_authority import (
    M6HearingModelCallAuthorityError,
    assemble_m6_locked_hearing_model_calls,
    derive_m6_hearing_model_call_authority_root,
)
from labcourt.contracts.backlog import BacklogItem
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import ArtifactKind, BacklogStatus, CaseStatus, VlmRole
from labcourt.contracts.hearing import (
    HearingBacklogCompletionReceipt,
    HearingBacklogRetryFailure,
    HearingBacklogRetrySuccess,
    HearingCheckpoint,
    HearingCycleScope,
    HearingHumanReviewReceipt,
    HearingInitialStrictParseFailureProof,
    HearingModelCacheEntry,
    HearingModelCallFailureAuthority,
    HearingModelParseReceipt,
    HearingModelRequest,
    HearingModelResponse,
    HearingPrecedentRetrievalReceipt,
    HearingRoleOutput,
    HearingRound,
    HearingSession,
    HearingStrictParseFailureAttempt,
    HearingStrictParseFailureProof,
    HearingUsageReceipt,
    validate_hearing_cycle_scope_binding,
)
from labcourt.ports.m6_model_calls import (
    M6M4ModelCacheAuthorityDocument,
    M6M4ModelCallAuthoritySnapshot,
    M6M4ModelCallFailureAuthorityDocument,
    M6M4ModelParseReceiptAuthorityDocument,
    M6M4ModelRequestAuthorityDocument,
    M6M4ModelResponseAuthorityDocument,
    M6M4ModelUsageAuthorityDocument,
    M6M4RoleOutputAuthorityDocument,
)

from ._readonly_m4_artifact_codec import (
    M4_TYPED_TABLES,
    M4DocumentFailure,
    M4IndexFailure,
    M4Record,
    M4TableSpec,
    load_m4_record,
)
from ._readonly_m4_artifact_relations import (
    _call_closure_matches,
    _parse_matches,
    _response_row_matches_request,
    _role_output_matches_call,
    _usage_row_matches_claim,
)
from ._sqlite_m6_live_read_cut import M6LiveReader
from ._sqlite_m6_upgrade_case_document import M6SQLiteCaseAuthorityDocument
from ._sqlite_m6_upgrade_m4_model_metadata import (
    build_m6_sqlite_m4_model_documents_plan,
)
from ._sqlite_m6_upgrade_m4_model_plan import (
    M6SQLiteM4DocumentRoute,
    M6SQLiteM4DocumentSlot,
    M6SQLiteM4FailureClosureKind,
    M6SQLiteM4HistoricalFailureBinding,
    M6SQLiteM4ModelDocumentFailureCode,
    M6SQLiteM4ModelDocumentsPlan,
    M6SQLiteM4SupportDocumentCommitmentKind,
    M6SQLiteM4SupportDocumentRoute,
    M6SQLiteM4SupportDocumentSlot,
    _plan_is_consistent,
)
from ._sqlite_m6_upgrade_m4_model_primitives import _active, _fail


@dataclass(frozen=True, slots=True)
class _BodyRoute:
    sql: str
    spec: M4TableSpec[BaseModel]
    rowid_key: str


@dataclass(frozen=True, slots=True)
class _BacklogBodyRoute:
    sql: str
    json_column: str
    id_column: str


@dataclass(frozen=True, slots=True)
class _BacklogRecord:
    row: sqlite3.Row
    artifact_id: str
    document: BacklogItem
    canonical_document: str


@dataclass(frozen=True, slots=True)
class _ReplayBody:
    route: str
    rowid: int
    artifact_id: str
    commitment_kind: str
    commitment_sha256: str
    canonical_sha256: str

    @property
    def projection(self) -> list[object]:
        return [
            self.route,
            self.rowid,
            self.artifact_id,
            self.commitment_kind,
            self.commitment_sha256,
            self.canonical_sha256,
        ]


@dataclass(frozen=True, slots=True)
class _FailureSupportDocuments:
    checkpoints: dict[str, HearingCheckpoint]
    backlog_items: dict[str, BacklogItem]
    backlog_versions: tuple[tuple[int, BacklogItem], ...]
    outcomes: dict[str, HearingBacklogRetrySuccess | HearingBacklogRetryFailure]
    completions: dict[str, HearingBacklogCompletionReceipt]
    attempts: dict[str, HearingStrictParseFailureAttempt]
    proofs: dict[
        str,
        HearingInitialStrictParseFailureProof | HearingStrictParseFailureProof,
    ]
    human_reviews: dict[str, HearingHumanReviewReceipt]


def _spec(table: str) -> M4TableSpec[BaseModel]:
    matches = tuple(value for value in M4_TYPED_TABLES if value.table == table)
    if len(matches) != 1:
        raise RuntimeError(f"M4 body route has no unique codec for {table}")
    return cast(M4TableSpec[BaseModel], matches[0])


_PRIMARY_ROUTES = {
    M6SQLiteM4DocumentRoute.MODEL_REQUEST: _BodyRoute(
        "SELECT rowid AS document_rowid, * FROM m4_model_call_claims "
        "WHERE rowid = ? AND request_id = ? LIMIT 2",
        _spec("m4_model_call_claims"),
        "document_rowid",
    ),
    M6SQLiteM4DocumentRoute.MODEL_RESPONSE: _BodyRoute(
        "SELECT rowid AS document_rowid, * FROM m4_model_responses "
        "WHERE rowid = ? AND response_id = ? LIMIT 2",
        _spec("m4_model_responses"),
        "document_rowid",
    ),
    M6SQLiteM4DocumentRoute.MODEL_CACHE_ENTRY: _BodyRoute(
        "SELECT rowid AS document_rowid, * FROM m4_model_cache "
        "WHERE rowid = ? AND cache_entry_id = ? LIMIT 2",
        _spec("m4_model_cache"),
        "document_rowid",
    ),
    M6SQLiteM4DocumentRoute.MODEL_PARSE_RECEIPT: _BodyRoute(
        "SELECT rowid AS document_rowid, * FROM m4_model_parse_receipts "
        "WHERE rowid = ? AND parse_receipt_id = ? LIMIT 2",
        _spec("m4_model_parse_receipts"),
        "document_rowid",
    ),
    M6SQLiteM4DocumentRoute.ROLE_OUTPUT: _BodyRoute(
        "SELECT rowid AS document_rowid, * FROM m4_parsed_hearing_outputs "
        "WHERE rowid = ? AND parsed_output_id = ? LIMIT 2",
        _spec("m4_parsed_hearing_outputs"),
        "document_rowid",
    ),
    M6SQLiteM4DocumentRoute.MODEL_USAGE: _BodyRoute(
        "SELECT rowid AS document_rowid, * FROM m4_hearing_usage_receipts "
        "WHERE rowid = ? AND usage_receipt_id = ? LIMIT 2",
        _spec("m4_hearing_usage_receipts"),
        "document_rowid",
    ),
    M6SQLiteM4DocumentRoute.MODEL_CALL_FAILURE: _BodyRoute(
        "SELECT rowid AS document_rowid, * FROM m4_model_call_failure_authorities "
        "WHERE rowid = ? AND authority_id = ? LIMIT 2",
        _spec("m4_model_call_failure_authorities"),
        "document_rowid",
    ),
}

_SUPPORT_ROUTES = {
    M6SQLiteM4SupportDocumentRoute.HEARING_SESSION: _BodyRoute(
        "SELECT rowid AS support_rowid, * FROM m4_hearings "
        "WHERE rowid = ? AND hearing_id = ? LIMIT 2",
        _spec("m4_hearings"),
        "support_rowid",
    ),
    M6SQLiteM4SupportDocumentRoute.HEARING_CYCLE: _BodyRoute(
        "SELECT rowid AS support_rowid, * FROM m4_hearing_cycles "
        "WHERE rowid = ? AND cycle_id = ? LIMIT 2",
        _spec("m4_hearing_cycles"),
        "support_rowid",
    ),
    M6SQLiteM4SupportDocumentRoute.PRECEDENT_RETRIEVAL: _BodyRoute(
        "SELECT rowid AS support_rowid, * FROM m4_precedent_retrieval_receipts "
        "WHERE rowid = ? AND retrieval_receipt_id = ? LIMIT 2",
        _spec("m4_precedent_retrieval_receipts"),
        "support_rowid",
    ),
    M6SQLiteM4SupportDocumentRoute.HEARING_ROUND: _BodyRoute(
        "SELECT rowid AS support_rowid, * FROM m4_hearing_rounds "
        "WHERE rowid = ? AND round_id = ? LIMIT 2",
        _spec("m4_hearing_rounds"),
        "support_rowid",
    ),
    M6SQLiteM4SupportDocumentRoute.HEARING_CHECKPOINT: _BodyRoute(
        "SELECT rowid AS support_rowid, * FROM m4_hearing_checkpoints "
        "WHERE rowid = ? AND checkpoint_id = ? LIMIT 2",
        _spec("m4_hearing_checkpoints"),
        "support_rowid",
    ),
    M6SQLiteM4SupportDocumentRoute.BACKLOG_RETRY_OUTCOME: _BodyRoute(
        "SELECT rowid AS support_rowid, * FROM m4_hearing_backlog_retry_outcomes "
        "WHERE rowid = ? AND outcome_id = ? LIMIT 2",
        _spec("m4_hearing_backlog_retry_outcomes"),
        "support_rowid",
    ),
    M6SQLiteM4SupportDocumentRoute.BACKLOG_COMPLETION_RECEIPT: _BodyRoute(
        "SELECT rowid AS support_rowid, * FROM m4_backlog_completion_receipts "
        "WHERE rowid = ? AND receipt_id = ? LIMIT 2",
        _spec("m4_backlog_completion_receipts"),
        "support_rowid",
    ),
    M6SQLiteM4SupportDocumentRoute.STRICT_PARSE_FAILURE_ATTEMPT: _BodyRoute(
        "SELECT rowid AS support_rowid, * FROM m4_hearing_strict_parse_failure_attempts "
        "WHERE rowid = ? AND attempt_id = ? LIMIT 2",
        _spec("m4_hearing_strict_parse_failure_attempts"),
        "support_rowid",
    ),
    M6SQLiteM4SupportDocumentRoute.STRICT_PARSE_FAILURE_PROOF: _BodyRoute(
        "SELECT rowid AS support_rowid, * FROM m4_hearing_strict_parse_failure_proofs "
        "WHERE rowid = ? AND proof_id = ? LIMIT 2",
        _spec("m4_hearing_strict_parse_failure_proofs"),
        "support_rowid",
    ),
    M6SQLiteM4SupportDocumentRoute.HEARING_HUMAN_REVIEW_RECEIPT: _BodyRoute(
        "SELECT rowid AS support_rowid, * FROM m4_hearing_human_review_receipts "
        "WHERE rowid = ? AND receipt_id = ? LIMIT 2",
        _spec("m4_hearing_human_review_receipts"),
        "support_rowid",
    ),
}

_BACKLOG_SUPPORT_ROUTES = {
    M6SQLiteM4SupportDocumentRoute.BACKLOG_ITEM: _BacklogBodyRoute(
        "SELECT rowid AS support_rowid, * FROM backlog_items "
        "WHERE rowid = ? AND item_id = ? LIMIT 2",
        "initial_json",
        "item_id",
    ),
    M6SQLiteM4SupportDocumentRoute.BACKLOG_ITEM_VERSION: _BacklogBodyRoute(
        "SELECT rowid AS support_rowid, * FROM backlog_item_versions "
        "WHERE rowid = ? AND document_sha256 = ? LIMIT 2",
        "item_json",
        "document_sha256",
    ),
}


def _row(
    connection: M6LiveReader,
    route: _BodyRoute,
    *,
    rowid: int,
    artifact_id: str,
) -> sqlite3.Row:
    return _exact_row(
        connection,
        route.sql,
        rowid_key=route.rowid_key,
        rowid=rowid,
        artifact_id=artifact_id,
    )


def _exact_row(
    connection: M6LiveReader,
    sql: str,
    *,
    rowid_key: str,
    rowid: int,
    artifact_id: str,
) -> sqlite3.Row:
    cursor = connection.execute(sql, (rowid, artifact_id))
    try:
        rows = tuple(cursor.fetchmany(2))
    finally:
        cursor.close()
    if len(rows) != 1 or rows[0][rowid_key] != rowid:
        _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    return rows[0]


def _canonical_bytes(raw: object, expected_bytes: int) -> bytes:
    if not isinstance(raw, str):
        _fail(M6SQLiteM4ModelDocumentFailureCode.DOCUMENT_INVALID)
    try:
        encoded = raw.encode("utf-8")
    except UnicodeError:
        _fail(M6SQLiteM4ModelDocumentFailureCode.DOCUMENT_INVALID)
    if len(encoded) != expected_bytes:
        _fail(M6SQLiteM4ModelDocumentFailureCode.DOCUMENT_INVALID)
    return encoded


def _load_primary(
    connection: M6LiveReader,
    slot: M6SQLiteM4DocumentSlot,
) -> tuple[M4Record, _ReplayBody]:
    route = _PRIMARY_ROUTES.get(slot.route)
    if route is None:
        _fail(M6SQLiteM4ModelDocumentFailureCode.PHYSICAL_PLAN_INVALID)
    row = _row(connection, route, rowid=slot.rowid, artifact_id=slot.artifact_id)
    encoded = _canonical_bytes(row[route.spec.json_column], slot.document_bytes)
    canonical_sha256 = hashlib.sha256(encoded).hexdigest()
    if canonical_sha256 != slot.document_sha256:
        _fail(M6SQLiteM4ModelDocumentFailureCode.DOCUMENT_INVALID)
    try:
        record = load_m4_record(row, route.spec)
    except M4DocumentFailure:
        _fail(M6SQLiteM4ModelDocumentFailureCode.DOCUMENT_INVALID)
    except M4IndexFailure:
        _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    if record.artifact_id != slot.artifact_id:
        _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    return record, _ReplayBody(
        route=slot.route.value,
        rowid=slot.rowid,
        artifact_id=slot.artifact_id,
        commitment_kind="CANONICAL_DOCUMENT",
        commitment_sha256=slot.document_sha256,
        canonical_sha256=canonical_sha256,
    )


def _support_semantic_sha256(document: BaseModel) -> str:
    if isinstance(document, HearingSession):
        return document.session_sha256
    if isinstance(document, HearingCycleScope):
        return document.cycle_sha256
    if isinstance(document, HearingPrecedentRetrievalReceipt):
        return document.receipt_sha256
    if isinstance(document, HearingRound):
        return document.round_id
    if isinstance(document, HearingCheckpoint):
        return document.checkpoint_sha256
    _fail(M6SQLiteM4ModelDocumentFailureCode.PHYSICAL_PLAN_INVALID)


def _backlog_index_matches(
    record: _BacklogRecord,
    route: M6SQLiteM4SupportDocumentRoute,
) -> bool:
    item = record.document
    common = (
        ("run_id", item.run_id),
        ("item_id", item.item_id),
    )
    if route == M6SQLiteM4SupportDocumentRoute.BACKLOG_ITEM:
        return _row_matches(
            record.row,
            (
                *common,
                ("case_id", item.case_id),
                ("stage", item.stage.value),
                ("role", item.role.value if item.role is not None else None),
                ("reason_code", item.reason_code.value),
                ("stage_input_kind", item.stage_input_ref.kind.value),
                ("stage_input_id", item.stage_input_ref.artifact_id),
                ("stage_input_sha256", item.stage_input_sha256),
                ("max_attempts", item.max_attempts),
                ("manifest_id", item.manifest_id),
            ),
        )
    if route != M6SQLiteM4SupportDocumentRoute.BACKLOG_ITEM_VERSION:
        return False
    expires_at = (
        item.lease_expires_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        if item.lease_expires_at is not None
        else None
    )
    return _row_matches(
        record.row,
        (
            *common,
            ("status", item.status.value),
            ("attempt_count", item.attempt_count),
            ("lease_id", item.lease_id),
            ("lease_owner_sha256", item.lease_owner_sha256),
            ("lease_expires_at", expires_at),
            ("retry_generation", item.retry_generation),
        ),
    )


def _load_backlog_support(
    connection: M6LiveReader,
    slot: M6SQLiteM4SupportDocumentSlot,
    route: _BacklogBodyRoute,
) -> tuple[_BacklogRecord, _ReplayBody]:
    row = _exact_row(
        connection,
        route.sql,
        rowid_key="support_rowid",
        rowid=slot.rowid,
        artifact_id=slot.artifact_id,
    )
    encoded = _canonical_bytes(row[route.json_column], slot.document_bytes)
    canonical_sha256 = hashlib.sha256(encoded).hexdigest()
    if (
        slot.commitment_kind != M6SQLiteM4SupportDocumentCommitmentKind.CANONICAL_DOCUMENT
        or canonical_sha256 != slot.body_commitment_sha256
    ):
        _fail(M6SQLiteM4ModelDocumentFailureCode.DOCUMENT_INVALID)
    raw = row[route.json_column]
    assert isinstance(raw, str)
    try:
        document = BacklogItem.model_validate_json(raw)
        canonical = canonical_json(document.model_dump(mode="json"))
    except (TypeError, ValueError, ValidationError, UnicodeError):
        _fail(M6SQLiteM4ModelDocumentFailureCode.DOCUMENT_INVALID)
    if canonical != raw:
        _fail(M6SQLiteM4ModelDocumentFailureCode.DOCUMENT_INVALID)
    record = _BacklogRecord(
        row=row,
        artifact_id=slot.artifact_id,
        document=document,
        canonical_document=canonical,
    )
    if row[route.id_column] != slot.artifact_id or not _backlog_index_matches(record, slot.route):
        _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    return record, _ReplayBody(
        route=slot.route.value,
        rowid=slot.rowid,
        artifact_id=slot.artifact_id,
        commitment_kind=slot.commitment_kind.value,
        commitment_sha256=slot.body_commitment_sha256,
        canonical_sha256=canonical_sha256,
    )


def _load_support(
    connection: M6LiveReader,
    slot: M6SQLiteM4SupportDocumentSlot,
) -> tuple[M4Record | _BacklogRecord, _ReplayBody]:
    route = _SUPPORT_ROUTES.get(slot.route)
    if route is None:
        backlog_route = _BACKLOG_SUPPORT_ROUTES.get(slot.route)
        if backlog_route is not None:
            return _load_backlog_support(connection, slot, backlog_route)
        _fail(M6SQLiteM4ModelDocumentFailureCode.PHYSICAL_PLAN_INVALID)
    row = _row(connection, route, rowid=slot.rowid, artifact_id=slot.artifact_id)
    encoded = _canonical_bytes(row[route.spec.json_column], slot.document_bytes)
    canonical_sha256 = hashlib.sha256(encoded).hexdigest()
    try:
        record = load_m4_record(row, route.spec)
    except M4DocumentFailure:
        _fail(M6SQLiteM4ModelDocumentFailureCode.DOCUMENT_INVALID)
    except M4IndexFailure:
        _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    if record.artifact_id != slot.artifact_id:
        _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    if slot.commitment_kind == M6SQLiteM4SupportDocumentCommitmentKind.SEMANTIC_DOCUMENT:
        commitment = _support_semantic_sha256(record.document)
    elif slot.commitment_kind == M6SQLiteM4SupportDocumentCommitmentKind.CANONICAL_DOCUMENT:
        commitment = canonical_sha256
    else:
        _fail(M6SQLiteM4ModelDocumentFailureCode.PHYSICAL_PLAN_INVALID)
    if commitment != slot.body_commitment_sha256:
        _fail(M6SQLiteM4ModelDocumentFailureCode.DOCUMENT_INVALID)
    return record, _ReplayBody(
        route=slot.route.value,
        rowid=slot.rowid,
        artifact_id=slot.artifact_id,
        commitment_kind=slot.commitment_kind.value,
        commitment_sha256=slot.body_commitment_sha256,
        canonical_sha256=canonical_sha256,
    )


def _cache_request(
    row: sqlite3.Row,
    slot: M6SQLiteM4DocumentSlot,
    claim: HearingModelRequest,
) -> _ReplayBody:
    if (
        slot.route != M6SQLiteM4DocumentRoute.MODEL_CACHE_REQUEST
        or row["document_rowid"] != slot.rowid
        or row["request_id"] != slot.artifact_id
    ):
        _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    raw = row["request_json"]
    encoded = _canonical_bytes(raw, slot.document_bytes)
    if hashlib.sha256(encoded).hexdigest() != slot.document_sha256:
        _fail(M6SQLiteM4ModelDocumentFailureCode.DOCUMENT_INVALID)
    assert isinstance(raw, str)
    try:
        duplicate = HearingModelRequest.model_validate_json(raw)
        canonical = canonical_json(duplicate.model_dump(mode="json"))
    except (TypeError, ValueError, ValidationError, UnicodeError):
        _fail(M6SQLiteM4ModelDocumentFailureCode.DOCUMENT_INVALID)
    if canonical != raw or duplicate != claim:
        _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    return _ReplayBody(
        route=slot.route.value,
        rowid=slot.rowid,
        artifact_id=slot.artifact_id,
        commitment_kind="CANONICAL_DOCUMENT",
        commitment_sha256=slot.document_sha256,
        canonical_sha256=slot.document_sha256,
    )


def _request_projection_matches(
    left: HearingModelRequest,
    right: HearingModelRequest,
) -> bool:
    try:
        return type(left) is type(right) and left.request_projection() == right.request_projection()
    except (AttributeError, TypeError, ValueError):
        return False


def _load_historical_failure(
    connection: M6LiveReader,
    binding: M6SQLiteM4HistoricalFailureBinding,
) -> tuple[HearingModelCallFailureAuthority, _ReplayBody]:
    route = _PRIMARY_ROUTES[M6SQLiteM4DocumentRoute.MODEL_CALL_FAILURE]
    row = _row(
        connection,
        route,
        rowid=binding.rowid,
        artifact_id=binding.authority_id,
    )
    encoded = _canonical_bytes(row[route.spec.json_column], binding.document_bytes)
    canonical_sha256 = hashlib.sha256(encoded).hexdigest()
    if canonical_sha256 != binding.document_sha256:
        _fail(M6SQLiteM4ModelDocumentFailureCode.DOCUMENT_INVALID)
    try:
        record = load_m4_record(row, route.spec)
    except M4DocumentFailure:
        _fail(M6SQLiteM4ModelDocumentFailureCode.DOCUMENT_INVALID)
    except M4IndexFailure:
        _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    authority = cast(HearingModelCallFailureAuthority, record.document)
    if record.artifact_id != binding.authority_id or not _historical_binding_matches(
        authority,
        binding,
    ):
        _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    return authority, _ReplayBody(
        route=binding.route.value,
        rowid=binding.rowid,
        artifact_id=binding.authority_id,
        commitment_kind="CANONICAL_DOCUMENT",
        commitment_sha256=binding.document_sha256,
        canonical_sha256=canonical_sha256,
    )


def _historical_binding_matches(
    authority: HearingModelCallFailureAuthority,
    binding: M6SQLiteM4HistoricalFailureBinding,
) -> bool:
    return (
        authority.authority_id == binding.authority_id
        and authority.request.request_id == binding.request_id
        and authority.claim_takeover_count == binding.claim_takeover_count
        and authority.hearing_session_id == binding.hearing_id
        and authority.request.cycle_scope_id == binding.cycle_scope_id
        and authority.request.cycle_scope_sha256 == binding.cycle_scope_sha256
        and authority.case_id == binding.case_id
        and authority.role.value == binding.role.value
        and authority.source_checkpoint_id == binding.source_checkpoint_id
        and authority.source_checkpoint_sha256 == binding.source_checkpoint_sha256
        and authority.source_checkpoint_version == binding.source_checkpoint_version
        and authority.backlog_item_id == binding.backlog_item_id
        and authority.backlog_version == binding.backlog_version
        and authority.retry_generation == binding.retry_generation
        and authority.closure_kind.value == binding.closure_kind.value
        and authority.completion_receipt_id == binding.completion_receipt_id
        and authority.closure_case_revision == binding.closure_case_revision
        and authority.closure_audit_sequence == binding.closure_audit_sequence
        and authority.closure_audit_entry_hash == binding.closure_audit_entry_hash
    )


def _current_failure_matches(
    authority: HearingModelCallFailureAuthority,
    *,
    request: HearingModelRequest,
    claim_record: M4Record,
    graph: object,
) -> bool:
    claim_takeover_count = getattr(graph, "claim_takeover_count", None)
    hearing_id = getattr(graph, "hearing_id", None)
    cycle_scope_id = getattr(graph, "cycle_scope_id", None)
    cycle_scope_sha256 = getattr(graph, "cycle_scope_sha256", None)
    role = getattr(getattr(graph, "observation", None), "role", None)
    return (
        authority.request == request
        and authority.request.request_id == request.request_id
        and authority.claim_takeover_count == claim_takeover_count
        and authority.hearing_session_id == hearing_id
        and authority.request.cycle_scope_id == cycle_scope_id
        and authority.request.cycle_scope_sha256 == cycle_scope_sha256
        and authority.role.value == getattr(role, "value", None)
        and authority.claim_owner_sha256 == claim_record.row["owner_token_sha256"]
        and authority.claim_lease_expires_at.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        == claim_record.row["lease_expires_at"]
    )


def _same_backlog_identity(left: BacklogItem, right: BacklogItem) -> bool:
    return (
        left.run_id == right.run_id
        and left.case_id == right.case_id
        and left.stage == right.stage
        and left.role == right.role
        and left.reason_code == right.reason_code
        and left.stage_input_ref == right.stage_input_ref
        and left.stage_input_sha256 == right.stage_input_sha256
        and left.max_attempts == right.max_attempts
        and left.manifest_id == right.manifest_id
        and left.item_id == right.item_id
    )


def _fresh_plan(
    connection: M6LiveReader,
    plan: M6SQLiteM4ModelDocumentsPlan,
) -> M6SQLiteM4ModelDocumentsPlan:
    if not _plan_is_consistent(plan) or not plan.hearing_model_bindings:
        _fail(M6SQLiteM4ModelDocumentFailureCode.PHYSICAL_PLAN_INVALID)
    role_bindings = plan.hearing_model_bindings[0].role_bindings
    if any(value.role_bindings != role_bindings for value in plan.hearing_model_bindings):
        _fail(M6SQLiteM4ModelDocumentFailureCode.PHYSICAL_PLAN_INVALID)
    try:
        authority = M6SQLiteCaseAuthorityDocument(
            candidate_case_binding=plan.selected_case_binding,
            case=plan.selected_case,
            canonical_case_document=canonical_json(plan.selected_case.model_dump(mode="json")),
            audit_entry=plan.selected_case_audit,
            canonical_audit_document=canonical_json(
                plan.selected_case_audit.model_dump(mode="json")
            ),
        )
    except (TypeError, ValueError, ValidationError, UnicodeError):
        _fail(M6SQLiteM4ModelDocumentFailureCode.PHYSICAL_PLAN_INVALID)
    fresh = build_m6_sqlite_m4_model_documents_plan(
        connection=connection,
        expected_run_id=plan.run_id,
        expected_manifest_id=plan.manifest_id,
        expected_role_model_manifests=role_bindings,
        selected_case_authority=authority,
        observed_model_calls=plan.observed_model_calls,
    )
    if fresh != plan:
        _fail(M6SQLiteM4ModelDocumentFailureCode.PHYSICAL_PLAN_INVALID)
    return fresh


def _optional_ref_id(value: object) -> str | None:
    artifact_id = getattr(value, "artifact_id", None)
    return artifact_id if isinstance(artifact_id, str) else None


def _row_matches(row: sqlite3.Row, expected: tuple[tuple[str, object], ...]) -> bool:
    try:
        return all(
            row[key] == (int(value) if isinstance(value, bool) else value)
            for key, value in expected
        )
    except (IndexError, KeyError):
        return False


def _retrieval_index_matches(
    record: M4Record,
    retrieval: HearingPrecedentRetrievalReceipt,
) -> bool:
    return _row_matches(
        record.row,
        (
            ("run_id", retrieval.run_id),
            ("retrieval_receipt_id", retrieval.receipt_id),
            ("hearing_id", retrieval.hearing_session_id),
            ("cycle_scope_id", retrieval.cycle_scope_id),
            ("cycle_scope_sha256", retrieval.cycle_scope_sha256),
            ("case_id", retrieval.case_id),
            ("prior_acquisition_rounds", retrieval.prior_acquisition_rounds),
            ("prior_rework_rounds", retrieval.prior_rework_rounds),
            ("current_pack_id", retrieval.current_evidence_pack_id),
            ("current_pack_version", retrieval.current_evidence_pack_version),
            ("evidence_class", retrieval.evidence_class.value),
            ("violation_type", retrieval.violation_type.value),
            ("rule_version", retrieval.rule_version),
            ("top_k", retrieval.top_k),
            ("initial_trigger_review_id", _optional_ref_id(retrieval.initial_trigger_review_ref)),
            (
                "initial_defect_codes_json",
                canonical_json([value.value for value in retrieval.initial_defect_codes]),
            ),
            ("rework_review_id", _optional_ref_id(retrieval.rework_review_ref)),
            (
                "rework_defect_codes_json",
                canonical_json([value.value for value in retrieval.rework_defect_codes]),
            ),
            (
                "candidate_precedent_refs_json",
                canonical_json(
                    [value.model_dump(mode="json") for value in retrieval.candidate_precedent_refs]
                ),
            ),
            ("candidate_snapshot_sha256", retrieval.candidate_snapshot_sha256),
            (
                "visible_precedent_refs_json",
                canonical_json(
                    [value.model_dump(mode="json") for value in retrieval.visible_precedent_refs]
                ),
            ),
            ("visible_snapshot_sha256", retrieval.visible_snapshot_sha256),
            (
                "scored_precedents_json",
                canonical_json(
                    [value.model_dump(mode="json") for value in retrieval.scored_precedents]
                ),
            ),
            ("retrieval_status", retrieval.status.value),
            (
                "degraded_reason",
                retrieval.degraded_reason.value if retrieval.degraded_reason is not None else None,
            ),
            ("precedent_retrieval_degraded", retrieval.status.value == "DEGRADED"),
            ("retriever_version", retrieval.retriever_version),
            ("retriever_manifest_id", retrieval.retriever_manifest_id),
            ("query_sha256", retrieval.query_sha256),
            ("embedding_model_manifest_id", retrieval.embedding_model_manifest_id),
            ("manifest_id", retrieval.manifest_id),
            ("document_sha256", retrieval.receipt_sha256),
        ),
    )


def _request_support_matches(
    request: HearingModelRequest,
    *,
    session: HearingSession,
    cycle: HearingCycleScope,
    retrieval: HearingPrecedentRetrievalReceipt,
) -> bool:
    try:
        validate_hearing_cycle_scope_binding(cycle, request)
        validate_hearing_cycle_scope_binding(cycle, retrieval)
    except (TypeError, ValueError):
        return False
    expected_model = {
        VlmRole.PROSECUTOR: session.prosecutor_model_manifest_id,
        VlmRole.DEFENDER: session.defender_model_manifest_id,
        VlmRole.JUDGE: session.judge_model_manifest_id,
    }.get(request.role)
    expected_precedents = tuple(
        sorted(
            (value.precedent.precedent_id for value in retrieval.scored_precedents),
        )
    )
    return (
        request.run_id == session.run_id == cycle.run_id == retrieval.run_id
        and request.case_id == session.case_id == cycle.case_id == retrieval.case_id
        and request.hearing_session_id
        == session.session_id
        == cycle.hearing_session_id
        == retrieval.hearing_session_id
        and request.manifest_id == session.manifest_id == cycle.manifest_id == retrieval.manifest_id
        and request.screening_ref.artifact_id == session.screening_id
        and request.hearing_prompt_bundle_sha256 == session.hearing_prompt_bundle_sha256
        and request.model_manifest_id == expected_model
        and request.evidence_class == retrieval.evidence_class
        and request.violation_type == retrieval.violation_type
        and request.precedent_retrieval_receipt_id == retrieval.receipt_id
        and request.precedent_retrieval_receipt_sha256 == retrieval.receipt_sha256
        and request.precedent_retrieval_degraded == (retrieval.status.value == "DEGRADED")
        and all(value.kind == ArtifactKind.PRECEDENT for value in request.allowed_precedent_refs)
        and tuple(value.artifact_id for value in request.allowed_precedent_refs)
        == expected_precedents
    )


def _upstream_matrix_matches(
    requests: dict[str, HearingModelRequest],
    outputs: dict[str, HearingRoleOutput],
) -> bool:
    def cycle_key(value: HearingModelRequest | HearingRoleOutput) -> tuple[object, ...]:
        return (
            value.hearing_session_id,
            value.round_index,
            value.prior_acquisition_rounds,
            value.prior_rework_rounds,
            value.current_evidence_pack_id,
            value.current_evidence_pack_version,
        )

    output_by_cycle_role = {(cycle_key(value), value.role): value for value in outputs.values()}
    if len(output_by_cycle_role) != len(outputs):
        return False
    for request in requests.values():
        prosecutor = output_by_cycle_role.get((cycle_key(request), VlmRole.PROSECUTOR))
        defender = output_by_cycle_role.get((cycle_key(request), VlmRole.DEFENDER))
        prosecutor_id = _optional_ref_id(request.prosecutor_output_ref)
        defender_id = _optional_ref_id(request.defender_output_ref)
        if request.role == VlmRole.PROSECUTOR:
            valid = prosecutor_id is None and defender_id is None
        elif request.role == VlmRole.DEFENDER:
            valid = (
                prosecutor is not None
                and prosecutor_id == prosecutor.output_id
                and defender_id is None
            )
        else:
            valid = (
                prosecutor is not None
                and defender is not None
                and prosecutor_id == prosecutor.output_id
                and defender_id == defender.output_id
            )
        if not valid:
            return False
    return True


def _call_relations_match(
    *,
    claim_record: M4Record,
    request: HearingModelRequest,
    response_record: M4Record,
    response: HearingModelResponse,
    cache_record: M4Record,
    cache: HearingModelCacheEntry,
    parse_record: M4Record,
    parse: HearingModelParseReceipt,
    usage_record: M4Record,
    usage: HearingUsageReceipt,
    output: HearingRoleOutput | None,
    retrieval: HearingPrecedentRetrievalReceipt,
) -> bool:
    row_scope = (
        ("cycle_scope_id", request.cycle_scope_id),
        ("cycle_scope_sha256", request.cycle_scope_sha256),
    )
    cache_matches = (
        cache.run_id == request.run_id
        and cache.case_id == request.case_id
        and cache.hearing_session_id == request.hearing_session_id
        and cache.round_index == request.round_index
        and cache.role == request.role
        and cache.current_evidence_pack_id == request.current_evidence_pack_id
        and cache.current_evidence_pack_version == request.current_evidence_pack_version
        and cache.cache_key == request.cache_key
        and cache.request_id == request.request_id
        and cache.request_sha256 == request.request_sha256
        and cache.response_id == response.response_id
        and cache.response_content_sha256 == response.content_sha256
        and cache.model_manifest_id == request.model_manifest_id
        and cache.prompt_manifest_id == request.prompt_manifest.prompt_manifest_id
        and cache.output_schema_sha256 == request.prompt_manifest.output_schema_sha256
        and cache.manifest_id == request.manifest_id
    )
    if not (
        _call_closure_matches(request, response, cache, usage)
        and cache_matches
        and _parse_matches(parse, request, response)
        and _response_row_matches_request(response_record, request)
        and _usage_row_matches_claim(usage_record, claim_record, request, usage)
        and _row_matches(cache_record.row, row_scope)
        and _row_matches(parse_record.row, row_scope)
        and _row_matches(usage_record.row, row_scope)
    ):
        return False
    return output is None or _role_output_matches_call(
        output,
        request,
        response,
        parse,
        retrieval,
    )


def _auxiliary_support_matches(support: _FailureSupportDocuments) -> bool:
    for proof in support.proofs.values():
        if any(support.attempts.get(value.attempt_id) != value for value in proof.attempts):
            return False
    for outcome in support.outcomes.values():
        if isinstance(outcome, HearingBacklogRetryFailure):
            strict_proof = outcome.strict_parse_failure
            if (
                strict_proof is not None
                and support.proofs.get(strict_proof.proof_id) != strict_proof
            ):
                return False
        human = outcome.human_review_receipt
        if human is not None and support.human_reviews.get(human.receipt_id) != human:
            return False
    return all(
        support.outcomes.get(value.outcome.outcome_id) == value.outcome
        for value in support.completions.values()
    )


def _failure_support_matches(
    authority: HearingModelCallFailureAuthority,
    *,
    request: HearingModelRequest,
    plan: M6SQLiteM4ModelDocumentsPlan,
    support: _FailureSupportDocuments,
    usages: tuple[M6M4ModelUsageAuthorityDocument, ...],
) -> bool:
    checkpoint = support.checkpoints.get(authority.source_checkpoint_id)
    initial = support.backlog_items.get(authority.backlog_item_id)
    versions = tuple(
        item
        for version, item in support.backlog_versions
        if item.item_id == authority.backlog_item_id and version == authority.backlog_version
    )
    if (
        not _request_projection_matches(authority.request, request)
        or checkpoint is None
        or checkpoint.checkpoint_sha256 != authority.source_checkpoint_sha256
        or checkpoint.version != authority.source_checkpoint_version
        or checkpoint.run_id != authority.run_id
        or checkpoint.case_id != authority.case_id
        or checkpoint.hearing_session_id != authority.hearing_session_id
        or checkpoint.cycle_scope_id != authority.request.cycle_scope_id
        or checkpoint.cycle_scope_sha256 != authority.request.cycle_scope_sha256
        or checkpoint.current_evidence_pack_id != authority.request.current_evidence_pack_id
        or checkpoint.current_evidence_pack_version
        != authority.request.current_evidence_pack_version
        or initial is None
        or len(versions) != 1
        or not _same_backlog_identity(initial, versions[0])
    ):
        return False
    version = versions[0]
    if (
        version.status != authority.backlog_status
        or version.attempt_count != authority.backlog_attempt_count
        or version.retry_generation != authority.retry_generation
    ):
        return False

    if authority.closure_case_revision == plan.selected_case_revision:
        expected_case_status = (
            CaseStatus.HUMAN_REVIEW
            if authority.backlog_status == BacklogStatus.EXHAUSTED
            else CaseStatus.BACKLOGGED
        )
        expected_current_item = (
            authority.backlog_item_id if authority.backlog_status == BacklogStatus.PENDING else None
        )
        if (
            plan.selected_case.status != expected_case_status
            or plan.selected_case.current_backlog_item_id != expected_current_item
            or plan.selected_case_audit.sequence != authority.closure_audit_sequence
            or plan.selected_case_audit.entry_hash != authority.closure_audit_entry_hash
        ):
            return False

    if authority.closure_kind.value == M6SQLiteM4FailureClosureKind.INITIAL_BACKLOG.value:
        return authority.completion_receipt_id is None and authority.lease is None
    completion_id = authority.completion_receipt_id
    if completion_id is None or authority.lease is None:
        return False
    completion = support.completions.get(completion_id)
    if completion is None:
        return False
    outcome = support.outcomes.get(completion.outcome.outcome_id)
    if (
        not isinstance(outcome, HearingBacklogRetryFailure)
        or completion.outcome != outcome
        or outcome.request != authority.request
        or outcome.lease != authority.lease
        or completion.backlog_status != authority.backlog_status
        or completion.source_checkpoint_id != authority.source_checkpoint_id
        or completion.source_checkpoint_sha256 != authority.source_checkpoint_sha256
        or completion.source_checkpoint_version != authority.source_checkpoint_version
        or completion.completion_case_revision != authority.closure_case_revision
        or completion.completion_audit_sequence != authority.closure_audit_sequence
        or completion.completion_audit_entry_hash != authority.closure_audit_entry_hash
    ):
        return False
    expected_response_ids = tuple(sorted(value.artifact_id for value in outcome.response_refs))
    actual_response_ids = tuple(
        sorted(
            value.receipt.response_ref.artifact_id
            for value in usages
            if value.receipt.response_ref.artifact_id in set(expected_response_ids)
        )
    )
    return actual_response_ids == expected_response_ids


def _replay_root(plan: M6SQLiteM4ModelDocumentsPlan, bodies: list[_ReplayBody]) -> str:
    projection = [
        "m6-sqlite-m4-replay-authority",
        1,
        plan.plan_identity_sha256,
        plan.run_id,
        plan.case_id,
        plan.manifest_id,
        [value.projection for value in sorted(bodies, key=lambda value: value.projection)],
    ]
    return hashlib.sha256(canonical_json(projection).encode("utf-8")).hexdigest()


def _validate_locked_projection(
    snapshot: M6M4ModelCallAuthoritySnapshot,
    plan: M6SQLiteM4ModelDocumentsPlan,
) -> None:
    try:
        locked = assemble_m6_locked_hearing_model_calls(
            source_case=plan.selected_case,
            snapshot=snapshot,
        )
    except (M6HearingModelCallAuthorityError, TypeError, ValueError, ValidationError):
        _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    by_request = {value.request_ref.artifact_id: value for value in locked}
    if set(by_request) != {value.request_id for value in plan.observed_model_calls}:
        _fail(M6SQLiteM4ModelDocumentFailureCode.OBSERVATION_CLOSURE_MISMATCH)
    for observation in plan.observed_model_calls:
        value = by_request[observation.request_id]
        if (
            value.layer != observation.layer
            or value.role != observation.role
            or value.attempt_index != observation.attempt_index
            or value.result_kind != observation.result_kind
        ):
            _fail(M6SQLiteM4ModelDocumentFailureCode.OBSERVATION_CLOSURE_MISMATCH)


def build_m6_sqlite_m4_model_call_authority_snapshot(
    *,
    connection: object,
    metadata_plan: object,
) -> M6M4ModelCallAuthoritySnapshot:
    """Decode the current M4 response slice without leaving the caller's B cut."""

    if type(connection) is not M6LiveReader or type(metadata_plan) is not (
        M6SQLiteM4ModelDocumentsPlan
    ):
        _fail(M6SQLiteM4ModelDocumentFailureCode.INVALID_ARGUMENT)
    assert isinstance(connection, M6LiveReader)
    assert isinstance(metadata_plan, M6SQLiteM4ModelDocumentsPlan)
    _active(connection)
    plan = _fresh_plan(connection, metadata_plan)

    replay_bodies: list[_ReplayBody] = []
    support_records: dict[
        M6SQLiteM4SupportDocumentRoute,
        dict[str, M4Record | _BacklogRecord],
    ] = {route: {} for route in M6SQLiteM4SupportDocumentRoute}
    read_support: set[tuple[M6SQLiteM4SupportDocumentRoute, int]] = set()
    for slot in plan.support_document_slots:
        record, replay = _load_support(connection, slot)
        support_records[slot.route][slot.artifact_id] = record
        replay_bodies.append(replay)
        read_support.add((slot.route, slot.rowid))
    if read_support != {(slot.route, slot.rowid) for slot in plan.support_document_slots}:
        _fail(M6SQLiteM4ModelDocumentFailureCode.PHYSICAL_PLAN_INVALID)

    sessions = {
        identity: record.document
        for identity, record in support_records[
            M6SQLiteM4SupportDocumentRoute.HEARING_SESSION
        ].items()
        if isinstance(record.document, HearingSession)
    }
    cycles = {
        identity: record.document
        for identity, record in support_records[
            M6SQLiteM4SupportDocumentRoute.HEARING_CYCLE
        ].items()
        if isinstance(record.document, HearingCycleScope)
    }
    retrievals = {
        identity: record.document
        for identity, record in support_records[
            M6SQLiteM4SupportDocumentRoute.PRECEDENT_RETRIEVAL
        ].items()
        if isinstance(record.document, HearingPrecedentRetrievalReceipt)
    }
    if (
        len(sessions) != len(support_records[M6SQLiteM4SupportDocumentRoute.HEARING_SESSION])
        or len(cycles) != len(support_records[M6SQLiteM4SupportDocumentRoute.HEARING_CYCLE])
        or len(retrievals)
        != len(support_records[M6SQLiteM4SupportDocumentRoute.PRECEDENT_RETRIEVAL])
        or any(
            not isinstance(record, M4Record)
            or not isinstance(record.document, HearingPrecedentRetrievalReceipt)
            or not _retrieval_index_matches(record, record.document)
            for record in support_records[
                M6SQLiteM4SupportDocumentRoute.PRECEDENT_RETRIEVAL
            ].values()
        )
    ):
        _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)

    checkpoints = {
        identity: record.document
        for identity, record in support_records[
            M6SQLiteM4SupportDocumentRoute.HEARING_CHECKPOINT
        ].items()
        if isinstance(record.document, HearingCheckpoint)
    }
    backlog_items = {
        record.document.item_id: record.document
        for record in support_records[M6SQLiteM4SupportDocumentRoute.BACKLOG_ITEM].values()
        if isinstance(record.document, BacklogItem)
    }
    backlog_versions = tuple(
        sorted(
            (
                (record.row["version"], record.document)
                for record in support_records[
                    M6SQLiteM4SupportDocumentRoute.BACKLOG_ITEM_VERSION
                ].values()
                if isinstance(record.document, BacklogItem) and type(record.row["version"]) is int
            ),
            key=lambda value: (value[1].item_id, value[0]),
        )
    )
    outcomes = {
        identity: record.document
        for identity, record in support_records[
            M6SQLiteM4SupportDocumentRoute.BACKLOG_RETRY_OUTCOME
        ].items()
        if isinstance(record.document, (HearingBacklogRetrySuccess, HearingBacklogRetryFailure))
    }
    completions = {
        identity: record.document
        for identity, record in support_records[
            M6SQLiteM4SupportDocumentRoute.BACKLOG_COMPLETION_RECEIPT
        ].items()
        if isinstance(record.document, HearingBacklogCompletionReceipt)
    }
    attempts = {
        identity: record.document
        for identity, record in support_records[
            M6SQLiteM4SupportDocumentRoute.STRICT_PARSE_FAILURE_ATTEMPT
        ].items()
        if isinstance(record.document, HearingStrictParseFailureAttempt)
    }
    proofs = {
        identity: record.document
        for identity, record in support_records[
            M6SQLiteM4SupportDocumentRoute.STRICT_PARSE_FAILURE_PROOF
        ].items()
        if isinstance(
            record.document,
            (HearingInitialStrictParseFailureProof, HearingStrictParseFailureProof),
        )
    }
    human_reviews = {
        identity: record.document
        for identity, record in support_records[
            M6SQLiteM4SupportDocumentRoute.HEARING_HUMAN_REVIEW_RECEIPT
        ].items()
        if isinstance(record.document, HearingHumanReviewReceipt)
    }
    typed_support_counts = (
        (checkpoints, M6SQLiteM4SupportDocumentRoute.HEARING_CHECKPOINT),
        (backlog_items, M6SQLiteM4SupportDocumentRoute.BACKLOG_ITEM),
        (outcomes, M6SQLiteM4SupportDocumentRoute.BACKLOG_RETRY_OUTCOME),
        (completions, M6SQLiteM4SupportDocumentRoute.BACKLOG_COMPLETION_RECEIPT),
        (attempts, M6SQLiteM4SupportDocumentRoute.STRICT_PARSE_FAILURE_ATTEMPT),
        (proofs, M6SQLiteM4SupportDocumentRoute.STRICT_PARSE_FAILURE_PROOF),
        (human_reviews, M6SQLiteM4SupportDocumentRoute.HEARING_HUMAN_REVIEW_RECEIPT),
    )
    if any(
        len(values) != len(support_records[route]) for values, route in typed_support_counts
    ) or (
        len(backlog_versions)
        != len(support_records[M6SQLiteM4SupportDocumentRoute.BACKLOG_ITEM_VERSION])
    ):
        _fail(M6SQLiteM4ModelDocumentFailureCode.DOCUMENT_INVALID)
    failure_support = _FailureSupportDocuments(
        checkpoints=checkpoints,
        backlog_items=backlog_items,
        backlog_versions=backlog_versions,
        outcomes=outcomes,
        completions=completions,
        attempts=attempts,
        proofs=proofs,
        human_reviews=human_reviews,
    )
    if not _auxiliary_support_matches(failure_support):
        _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)

    requests: list[M6M4ModelRequestAuthorityDocument] = []
    responses: list[M6M4ModelResponseAuthorityDocument] = []
    caches: list[M6M4ModelCacheAuthorityDocument] = []
    parses: list[M6M4ModelParseReceiptAuthorityDocument] = []
    outputs: list[M6M4RoleOutputAuthorityDocument] = []
    failures: list[M6M4ModelCallFailureAuthorityDocument] = []
    usages: list[M6M4ModelUsageAuthorityDocument] = []
    typed_requests: dict[str, HearingModelRequest] = {}
    claim_records: dict[str, M4Record] = {}
    typed_outputs: dict[str, HearingRoleOutput] = {}
    historical_authorities: dict[
        str,
        list[tuple[int, HearingModelCallFailureAuthority]],
    ] = {}
    current_failure_authorities: dict[str, HearingModelCallFailureAuthority] = {}
    read_primary: set[tuple[M6SQLiteM4DocumentRoute, int]] = set()

    for graph in plan.call_graphs:
        claim_record, replay = _load_primary(connection, graph.request)
        request = cast(HearingModelRequest, claim_record.document)
        if request.request_id in typed_requests:
            _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        replay_bodies.append(replay)
        read_primary.add((graph.request.route, graph.request.rowid))
        typed_requests[request.request_id] = request
        claim_records[request.request_id] = claim_record
        requests.append(
            M6M4ModelRequestAuthorityDocument(
                request=request,
                document_sha256=graph.request.document_sha256,
            )
        )

        session = sessions.get(graph.hearing_id)
        cycle = cycles.get(graph.cycle_scope_id)
        retrieval = retrievals.get(graph.retrieval_receipt_id)
        if (
            request.request_id != graph.observation.request_id
            or session is None
            or cycle is None
            or retrieval is None
            or not _request_support_matches(
                request,
                session=session,
                cycle=cycle,
                retrieval=retrieval,
            )
        ):
            _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)

    for binding in plan.historical_failures:
        authority, replay = _load_historical_failure(connection, binding)
        claim_request = typed_requests.get(binding.request_id)
        if claim_request is None or not _request_projection_matches(
            claim_request,
            authority.request,
        ):
            _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        historical_authorities.setdefault(binding.request_id, []).append(
            (binding.claim_takeover_count, authority)
        )
        replay_bodies.append(replay)
        read_primary.add((binding.route, binding.rowid))

    for request_id, values in historical_authorities.items():
        claim_request = typed_requests[request_id]
        if any(
            not _request_projection_matches(claim_request, authority.request)
            for _epoch, authority in sorted(values, key=lambda value: value[0])
        ):
            _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)

    for graph in plan.call_graphs:
        request = typed_requests[graph.observation.request_id]
        claim_record = claim_records[graph.observation.request_id]
        if graph.failure is not None:
            failure_record, replay = _load_primary(connection, graph.failure)
            authority = cast(HearingModelCallFailureAuthority, failure_record.document)
            if authority.authority_id != graph.failure.artifact_id or not _current_failure_matches(
                authority,
                request=request,
                claim_record=claim_record,
                graph=graph,
            ):
                _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
            replay_bodies.append(replay)
            read_primary.add((graph.failure.route, graph.failure.rowid))
            current_failure_authorities[request.request_id] = authority
            failures.append(
                M6M4ModelCallFailureAuthorityDocument(
                    authority=authority,
                    document_sha256=graph.failure.document_sha256,
                )
            )
            continue

        required = (
            graph.response,
            graph.cache_request,
            graph.cache,
            graph.parse_receipt,
            graph.usage,
        )
        if any(value is None for value in required):
            _fail(M6SQLiteM4ModelDocumentFailureCode.PHYSICAL_PLAN_INVALID)
        assert graph.response is not None
        assert graph.cache_request is not None
        assert graph.cache is not None
        assert graph.parse_receipt is not None
        assert graph.usage is not None

        response_record, replay = _load_primary(connection, graph.response)
        response = cast(HearingModelResponse, response_record.document)
        replay_bodies.append(replay)
        read_primary.add((graph.response.route, graph.response.rowid))
        responses.append(
            M6M4ModelResponseAuthorityDocument(
                response=response,
                document_sha256=graph.response.document_sha256,
            )
        )

        if graph.cache.rowid != graph.cache_request.rowid:
            _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        cache_record, replay = _load_primary(connection, graph.cache)
        cache = cast(HearingModelCacheEntry, cache_record.document)
        replay_bodies.extend(
            (replay, _cache_request(cache_record.row, graph.cache_request, request))
        )
        read_primary.add((graph.cache.route, graph.cache.rowid))
        read_primary.add((graph.cache_request.route, graph.cache_request.rowid))
        caches.append(
            M6M4ModelCacheAuthorityDocument(
                entry=cache,
                document_sha256=graph.cache.document_sha256,
            )
        )

        parse_record, replay = _load_primary(connection, graph.parse_receipt)
        parse = cast(HearingModelParseReceipt, parse_record.document)
        replay_bodies.append(replay)
        read_primary.add((graph.parse_receipt.route, graph.parse_receipt.rowid))
        parses.append(
            M6M4ModelParseReceiptAuthorityDocument(
                receipt=parse,
                document_sha256=graph.parse_receipt.document_sha256,
            )
        )

        output: HearingRoleOutput | None = None
        if graph.role_output is not None:
            output_record, replay = _load_primary(connection, graph.role_output)
            output = cast(HearingRoleOutput, output_record.document)
            replay_bodies.append(replay)
            read_primary.add((graph.role_output.route, graph.role_output.rowid))
            typed_outputs[output.output_id] = output
            outputs.append(
                M6M4RoleOutputAuthorityDocument(
                    output=output,
                    document_sha256=graph.role_output.document_sha256,
                )
            )

        usage_record, replay = _load_primary(connection, graph.usage)
        usage = cast(HearingUsageReceipt, usage_record.document)
        replay_bodies.append(replay)
        read_primary.add((graph.usage.route, graph.usage.rowid))
        usages.append(
            M6M4ModelUsageAuthorityDocument(
                receipt=usage,
                document_sha256=graph.usage.document_sha256,
            )
        )

        session = sessions.get(graph.hearing_id)
        cycle = cycles.get(graph.cycle_scope_id)
        retrieval = retrievals.get(graph.retrieval_receipt_id)
        if (
            session is None
            or cycle is None
            or retrieval is None
            or not _request_support_matches(
                request,
                session=session,
                cycle=cycle,
                retrieval=retrieval,
            )
            or not _call_relations_match(
                claim_record=claim_record,
                request=request,
                response_record=response_record,
                response=response,
                cache_record=cache_record,
                cache=cache,
                parse_record=parse_record,
                parse=parse,
                usage_record=usage_record,
                usage=usage,
                output=output,
                retrieval=retrieval,
            )
        ):
            _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)

    expected_primary = {(slot.route, slot.rowid) for slot in plan.document_slots} | {
        (value.route, value.rowid) for value in plan.historical_failures
    }
    if read_primary != expected_primary:
        _fail(M6SQLiteM4ModelDocumentFailureCode.PHYSICAL_PLAN_INVALID)
    if not _upstream_matrix_matches(typed_requests, typed_outputs):
        _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)

    ordered_requests = tuple(sorted(requests, key=lambda value: value.request.request_id))
    ordered_responses = tuple(sorted(responses, key=lambda value: value.response.response_id))
    ordered_caches = tuple(sorted(caches, key=lambda value: value.entry.cache_entry_id))
    ordered_parses = tuple(sorted(parses, key=lambda value: value.receipt.parse_receipt_id))
    ordered_outputs = tuple(sorted(outputs, key=lambda value: value.output.output_id))
    ordered_usages = tuple(sorted(usages, key=lambda value: value.receipt.usage_receipt_id))
    ordered_failures = tuple(sorted(failures, key=lambda value: value.authority.authority_id))
    all_authorities = [
        (typed_requests[request_id], authority)
        for request_id, values in historical_authorities.items()
        for _epoch, authority in values
    ] + [
        (typed_requests[request_id], authority)
        for request_id, authority in current_failure_authorities.items()
    ]
    if any(
        not _failure_support_matches(
            authority,
            request=request,
            plan=plan,
            support=failure_support,
            usages=ordered_usages,
        )
        for request, authority in all_authorities
    ):
        _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    replay_root = _replay_root(plan, replay_bodies)
    call_root = derive_m6_hearing_model_call_authority_root(
        source_identity_sha256=plan.plan_identity_sha256,
        run_id=plan.run_id,
        case_id=plan.case_id,
        manifest_id=plan.manifest_id,
        m4_replay_authority_root_sha256=replay_root,
        requests=ordered_requests,
        responses=ordered_responses,
        caches=ordered_caches,
        usages=ordered_usages,
        parse_receipts=ordered_parses,
        role_outputs=ordered_outputs,
        failures=ordered_failures,
    )
    try:
        snapshot = M6M4ModelCallAuthoritySnapshot(
            source_identity_sha256=plan.plan_identity_sha256,
            m4_replay_authority_root_sha256=replay_root,
            model_call_authority_root_sha256=call_root,
            run_id=plan.run_id,
            case_id=plan.case_id,
            manifest_id=plan.manifest_id,
            requests=ordered_requests,
            responses=ordered_responses,
            caches=ordered_caches,
            parse_receipts=ordered_parses,
            role_outputs=ordered_outputs,
            failures=ordered_failures,
            usages=ordered_usages,
            authority_failure_count=0,
        )
    except (TypeError, ValueError):
        _fail(M6SQLiteM4ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    _validate_locked_projection(snapshot, plan)
    _active(connection)
    return snapshot


__all__ = ["build_m6_sqlite_m4_model_call_authority_snapshot"]
