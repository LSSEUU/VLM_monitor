"""Strict same-snapshot decoding for a frozen M3 model-document plan."""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Callable
from typing import Protocol, TypeVar, cast

from pydantic import BaseModel, ValidationError

from labcourt.application.m6_model_call_authority import (
    M6ModelCallAuthorityError,
    assemble_m6_locked_screening_model_calls,
)
from labcourt.contracts.backlog import BacklogCompletionReceipt
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import UsageSummary
from labcourt.contracts.enums import ArtifactKind
from labcourt.contracts.model_call_failures import ModelCallFailureAuthority
from labcourt.contracts.screening import (
    ModelCacheEntry,
    ModelParseReceipt,
    ParsedScreeningOutput,
    VLMCallRequest,
    VLMResponse,
)
from labcourt.ports.m6_model_calls import (
    M6M3ModelCacheAuthorityDocument,
    M6M3ModelCallAuthoritySnapshot,
    M6M3ModelCallFailureAuthorityDocument,
    M6M3ModelParseReceiptAuthorityDocument,
    M6M3ModelRequestAuthorityDocument,
    M6M3ModelResponseAuthorityDocument,
    M6M3ModelUsageAuthorityDocument,
    M6M3ParsedOutputAuthorityDocument,
)

from ._readonly_m3_artifact_codec import (
    _DocumentFailure,
    _IndexFailure,
    _load_document,
    _load_request_document,
    _operational_context_is_authorized,
    _validate_cache_index,
    _validate_claim_index,
    _validate_completion_receipt_index,
    _validate_failure_authority_index,
    _validate_parse_receipt_index,
    _validate_parsed_output_index,
    _validate_response_index,
    _validate_usage_index,
)
from ._sqlite_m6_live_read_cut import M6LiveReader
from ._sqlite_m6_upgrade_case_document import M6SQLiteCaseAuthorityDocument
from ._sqlite_m6_upgrade_m3_model_metadata import (
    build_m6_sqlite_m3_model_documents_plan,
)
from ._sqlite_m6_upgrade_m3_model_plan import (
    M6SQLiteM3DocumentRoute,
    M6SQLiteM3ModelDocumentFailureCode,
    M6SQLiteM3ModelDocumentsPlan,
    M6SQLiteM3SupportDocumentRoute,
    _plan_is_consistent,
)
from ._sqlite_m6_upgrade_m3_model_primitives import _active, _fail

_ModelT = TypeVar("_ModelT", bound=BaseModel)
_IndexValidator = Callable[[sqlite3.Row, BaseModel], None]


class _BodyCommitment(Protocol):
    @property
    def rowid(self) -> int: ...

    @property
    def document_sha256(self) -> str: ...

    @property
    def document_bytes(self) -> int: ...


_CLAIM_SQL = """
SELECT rowid AS document_rowid, run_id, request_id, request_sha256,
       cache_key, case_id, evidence_pack_id, evidence_pack_version,
       purpose, model_manifest_id, manifest_id, request_json,
       request_document_sha256, status, owner_token_sha256,
       lease_expires_at, takeover_count, created_at, response_id,
       completed_at
FROM model_call_claims WHERE rowid = ? LIMIT 2
"""

_RESPONSE_SQL = """
SELECT rowid AS document_rowid, run_id, response_id, case_id,
       evidence_pack_id, evidence_pack_version, request_id,
       request_sha256, cache_key, purpose, attempt_index,
       raw_response_ref, content_sha256, size_bytes, model_manifest_id,
       manifest_id, response_json, document_sha256
FROM model_responses WHERE rowid = ? LIMIT 2
"""

_CACHE_SQL = """
SELECT rowid AS document_rowid, run_id, cache_key, cache_entry_id,
       case_id, evidence_pack_id, evidence_pack_version, request_id,
       request_sha256, response_id, response_content_sha256,
       model_manifest_id, prompt_manifest_id, output_schema_sha256,
       manifest_id, request_json, request_document_sha256, entry_json,
       document_sha256
FROM model_cache WHERE rowid = ? LIMIT 2
"""

_PARSE_RECEIPT_SQL = """
SELECT rowid AS document_rowid, run_id, parse_receipt_id, case_id,
       evidence_pack_id, evidence_pack_version, request_id, response_id,
       attempt_index, status, parsed_output_id, parsed_output_sha256,
       repair_request_id, manifest_id, receipt_json, document_sha256
FROM model_parse_receipts WHERE rowid = ? LIMIT 2
"""

_PARSED_OUTPUT_SQL = """
SELECT rowid AS document_rowid, run_id, parsed_output_id, case_id,
       evidence_pack_id, evidence_pack_version, request_id, response_id,
       response_content_sha256, output_schema_sha256, model_payload_sha256,
       parsed_output_sha256, manifest_id, output_json, document_sha256
FROM parsed_screening_outputs WHERE rowid = ? LIMIT 2
"""

_FAILURE_SQL = """
SELECT rowid AS document_rowid, run_id, authority_id, request_id,
       request_sha256, request_document_sha256, cache_key, case_id,
       evidence_pack_id, evidence_pack_version, purpose, model_manifest_id,
       claim_owner_sha256, claim_lease_expires_at, claim_takeover_count,
       failure_code, delivery_certainty, backlog_reason_code,
       backlog_item_id, backlog_version, backlog_status,
       backlog_attempt_count, retry_generation, closure_kind,
       completion_receipt_id, closure_case_revision,
       closure_audit_sequence, closure_audit_entry_hash, manifest_id,
       recorded_at, authority_json, document_sha256
FROM model_call_failure_authorities WHERE rowid = ? LIMIT 2
"""

_USAGE_SQL = """
SELECT rowid AS document_rowid, run_id, request_id, response_id,
       case_id, case_revision, consumer_kind, consumer_id, accounted_at,
       input_images, input_pixels, input_tokens, output_tokens,
       provider_latency_ms, retries, estimated_cost, usage_json,
       document_sha256
FROM model_call_usage_accounting WHERE rowid = ? LIMIT 2
"""

_COMPLETION_SQL = """
SELECT rowid AS support_rowid, run_id, receipt_id, item_id, case_id,
       outcome_kind, outcome_id, lease_identity_sha256, lease_id,
       attempt_count, retry_generation, backlog_status, backlog_version,
       completion_kind, completion_id, completion_case_status,
       completion_case_revision, completion_audit_sequence,
       completion_audit_entry_hash, manifest_id, receipt_json,
       document_sha256
FROM backlog_completion_receipts WHERE rowid = ? LIMIT 2
"""


def _row(connection: M6LiveReader, sql: str, rowid: int) -> sqlite3.Row:
    cursor = connection.execute(sql, (rowid,))
    try:
        rows = tuple(cursor.fetchmany(2))
    finally:
        cursor.close()
    if len(rows) != 1:
        _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    return rows[0]


def _verify_body(
    row: sqlite3.Row,
    *,
    rowid_key: str,
    json_key: str,
    commitment: _BodyCommitment,
) -> None:
    raw = row[json_key]
    if row[rowid_key] != commitment.rowid or not isinstance(raw, str):
        _fail(M6SQLiteM3ModelDocumentFailureCode.DOCUMENT_INVALID)
    try:
        encoded = raw.encode("utf-8")
    except UnicodeError:
        _fail(M6SQLiteM3ModelDocumentFailureCode.DOCUMENT_INVALID)
    if (
        len(encoded) != commitment.document_bytes
        or hashlib.sha256(encoded).hexdigest() != commitment.document_sha256
    ):
        _fail(M6SQLiteM3ModelDocumentFailureCode.DOCUMENT_INVALID)


def _request(
    row: sqlite3.Row,
    *,
    json_key: str,
    sha256_key: str,
    commitment: _BodyCommitment,
) -> VLMCallRequest:
    _verify_body(
        row,
        rowid_key="document_rowid",
        json_key=json_key,
        commitment=commitment,
    )
    try:
        return _load_request_document(row, json_key=json_key, sha256_key=sha256_key)
    except _DocumentFailure:
        _fail(M6SQLiteM3ModelDocumentFailureCode.DOCUMENT_INVALID)


def _document(
    row: sqlite3.Row,
    *,
    json_key: str,
    sha256_key: str,
    model_type: type[_ModelT],
    commitment: _BodyCommitment,
    rowid_key: str = "document_rowid",
) -> _ModelT:
    _verify_body(
        row,
        rowid_key=rowid_key,
        json_key=json_key,
        commitment=commitment,
    )
    try:
        return cast(
            _ModelT,
            _load_document(
                row,
                json_key=json_key,
                sha256_key=sha256_key,
                model_type=model_type,
            ),
        )
    except _DocumentFailure:
        _fail(M6SQLiteM3ModelDocumentFailureCode.DOCUMENT_INVALID)


def _index(
    validator: _IndexValidator,
    row: sqlite3.Row,
    document: BaseModel,
) -> None:
    try:
        validator(row, document)
    except _IndexFailure:
        _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)


def _fresh_plan(
    connection: M6LiveReader,
    plan: M6SQLiteM3ModelDocumentsPlan,
) -> M6SQLiteM3ModelDocumentsPlan:
    if not _plan_is_consistent(plan):
        _fail(M6SQLiteM3ModelDocumentFailureCode.PHYSICAL_PLAN_INVALID)
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
        _fail(M6SQLiteM3ModelDocumentFailureCode.PHYSICAL_PLAN_INVALID)
    fresh = build_m6_sqlite_m3_model_documents_plan(
        connection=connection,
        expected_run_id=plan.run_id,
        expected_manifest_id=plan.manifest_id,
        expected_model_manifest_id=plan.model_manifest_id,
        selected_case_authority=authority,
        observed_model_calls=plan.observed_model_calls,
    )
    if fresh != plan:
        _fail(M6SQLiteM3ModelDocumentFailureCode.PHYSICAL_PLAN_INVALID)
    return fresh


def _completion_usage_consumer(
    receipt: BacklogCompletionReceipt,
    plan: M6SQLiteM3ModelDocumentsPlan,
) -> tuple[str, str]:
    completion = receipt.completion_ref
    if completion.kind == ArtifactKind.BACKLOG_ITEM:
        return completion.kind.value, completion.artifact_id
    if completion.kind == ArtifactKind.SCREENING_RESULT:
        return completion.kind.value, completion.artifact_id
    if completion.kind != ArtifactKind.PROCEDURAL_REVIEW:
        _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    reviews = tuple(
        value
        for value in plan.selected_case.procedural_reviews
        if value.review_id == completion.artifact_id
    )
    if len(reviews) != 1:
        _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    review = reviews[0]
    verdicts = tuple(
        value
        for value in plan.selected_case.verdicts
        if value.verdict_id == review.reviewed_verdict_id
        and value.version == review.reviewed_verdict_version
        and value.verdict_sha256 == review.reviewed_verdict_sha256
    )
    if len(verdicts) != 1:
        _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    return ArtifactKind.SCREENING_RESULT.value, verdicts[0].screening_id


def _validate_completion_responses(
    receipt: BacklogCompletionReceipt,
    plan: M6SQLiteM3ModelDocumentsPlan,
    usages: tuple[M6M3ModelUsageAuthorityDocument, ...],
) -> None:
    consumer_kind, consumer_id = _completion_usage_consumer(receipt, plan)
    item_id = receipt.outcome.lease.item_id
    actual = tuple(
        sorted(
            {
                value.response_id
                for value in usages
                if (
                    receipt.outcome.outcome_kind == "SUCCESS"
                    and value.consumer_kind == ArtifactKind.BACKLOG_ITEM.value
                    and value.consumer_id == item_id
                )
                or (
                    value.case_revision == receipt.completion_case_revision
                    and value.consumer_kind == consumer_kind
                    and value.consumer_id == consumer_id
                )
            }
        )
    )
    expected = tuple(sorted(value.artifact_id for value in receipt.outcome.response_refs))
    if actual != expected:
        _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)


def _validate_locked_projection(
    snapshot: M6M3ModelCallAuthoritySnapshot,
    plan: M6SQLiteM3ModelDocumentsPlan,
) -> None:
    try:
        locked = assemble_m6_locked_screening_model_calls(
            source_case=plan.selected_case,
            snapshot=snapshot,
        )
    except (M6ModelCallAuthorityError, TypeError, ValueError, ValidationError):
        _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    by_request = {value.request_ref.artifact_id: value for value in locked}
    if set(by_request) != {value.request_id for value in plan.observed_model_calls}:
        _fail(M6SQLiteM3ModelDocumentFailureCode.OBSERVATION_CLOSURE_MISMATCH)
    for observation in plan.observed_model_calls:
        value = by_request[observation.request_id]
        if (
            value.layer != observation.layer
            or value.role != observation.role
            or value.attempt_index != observation.attempt_index
            or value.result_kind != observation.result_kind
        ):
            _fail(M6SQLiteM3ModelDocumentFailureCode.OBSERVATION_CLOSURE_MISMATCH)


def build_m6_sqlite_m3_model_call_authority_snapshot(
    *,
    connection: object,
    metadata_plan: object,
) -> M6M3ModelCallAuthoritySnapshot:
    """Decode a canonical snapshot while preserving the caller's B transaction."""

    if type(connection) is not M6LiveReader or type(metadata_plan) is not (
        M6SQLiteM3ModelDocumentsPlan
    ):
        _fail(M6SQLiteM3ModelDocumentFailureCode.INVALID_ARGUMENT)
    assert isinstance(connection, M6LiveReader)
    assert isinstance(metadata_plan, M6SQLiteM3ModelDocumentsPlan)
    _active(connection)
    plan = _fresh_plan(connection, metadata_plan)

    request_documents: list[M6M3ModelRequestAuthorityDocument] = []
    claim_requests: dict[str, VLMCallRequest] = {}
    read_primary: set[tuple[M6SQLiteM3DocumentRoute, int]] = set()
    for graph in plan.call_graphs:
        row = _row(connection, _CLAIM_SQL, graph.request.rowid)
        request = _request(
            row,
            json_key="request_json",
            sha256_key="request_document_sha256",
            commitment=graph.request,
        )
        _index(_validate_claim_index, row, cast(BaseModel, request))
        if request.request_id != graph.observation.request_id:
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        claim_requests[request.request_id] = request
        request_documents.append(
            M6M3ModelRequestAuthorityDocument(
                request=request,
                document_sha256=graph.request.document_sha256,
            )
        )
        read_primary.add((graph.request.route, graph.request.rowid))

    historical: dict[str, list[tuple[int, ModelCallFailureAuthority]]] = {}
    for binding in plan.historical_failures:
        row = _row(connection, _FAILURE_SQL, binding.rowid)
        authority = _document(
            row,
            json_key="authority_json",
            sha256_key="document_sha256",
            model_type=ModelCallFailureAuthority,
            commitment=binding,
        )
        _index(_validate_failure_authority_index, row, authority)
        if (
            authority.request.request_id != binding.request_id
            or authority.claim_takeover_count != binding.claim_takeover_count
            or authority.authority_id != binding.authority_id
            or authority.backlog_item_id != binding.backlog_item_id
            or authority.backlog_version != binding.backlog_version
            or authority.closure_kind.value != binding.closure_kind
            or authority.closure_case_revision != binding.closure_case_revision
        ):
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        historical.setdefault(binding.request_id, []).append(
            (binding.claim_takeover_count, authority)
        )
        read_primary.add((binding.route, binding.rowid))

    for request_id, values in historical.items():
        claim_request = claim_requests.get(request_id)
        if claim_request is None:
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        prior: list[ModelCallFailureAuthority] = []
        for _epoch, authority in sorted(values, key=lambda value: value[0]):
            if not _operational_context_is_authorized(claim_request, authority.request, prior):
                _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
            prior.append(authority)

    responses: list[M6M3ModelResponseAuthorityDocument] = []
    caches: list[M6M3ModelCacheAuthorityDocument] = []
    parse_receipts: list[M6M3ModelParseReceiptAuthorityDocument] = []
    parsed_outputs: list[M6M3ParsedOutputAuthorityDocument] = []
    failures: list[M6M3ModelCallFailureAuthorityDocument] = []
    usages: list[M6M3ModelUsageAuthorityDocument] = []
    for graph in plan.call_graphs:
        request_id = graph.observation.request_id
        claim_request = claim_requests[request_id]
        prior_authorities = [
            value
            for _epoch, value in sorted(
                historical.get(request_id, ()),
                key=lambda item: item[0],
            )
        ]
        if graph.failure is not None:
            row = _row(connection, _FAILURE_SQL, graph.failure.rowid)
            authority = _document(
                row,
                json_key="authority_json",
                sha256_key="document_sha256",
                model_type=ModelCallFailureAuthority,
                commitment=graph.failure,
            )
            _index(_validate_failure_authority_index, row, authority)
            if (
                authority.authority_id != graph.failure.artifact_id
                or authority.claim_takeover_count != graph.claim_takeover_count
                or not _operational_context_is_authorized(
                    claim_request,
                    authority.request,
                    prior_authorities,
                )
            ):
                _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
            failures.append(
                M6M3ModelCallFailureAuthorityDocument(
                    authority=authority,
                    document_sha256=graph.failure.document_sha256,
                )
            )
            read_primary.add((graph.failure.route, graph.failure.rowid))
            continue

        if any(
            value is None
            for value in (graph.response, graph.cache_request, graph.cache, graph.parse_receipt)
        ):
            _fail(M6SQLiteM3ModelDocumentFailureCode.PHYSICAL_PLAN_INVALID)
        assert graph.response is not None
        assert graph.cache_request is not None
        assert graph.cache is not None
        assert graph.parse_receipt is not None

        response_row = _row(connection, _RESPONSE_SQL, graph.response.rowid)
        response = _document(
            response_row,
            json_key="response_json",
            sha256_key="document_sha256",
            model_type=VLMResponse,
            commitment=graph.response,
        )
        _index(_validate_response_index, response_row, response)
        responses.append(
            M6M3ModelResponseAuthorityDocument(
                response=response,
                document_sha256=graph.response.document_sha256,
            )
        )
        read_primary.add((graph.response.route, graph.response.rowid))

        if graph.cache_request.rowid != graph.cache.rowid:
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        cache_row = _row(connection, _CACHE_SQL, graph.cache.rowid)
        cache_request = _request(
            cache_row,
            json_key="request_json",
            sha256_key="request_document_sha256",
            commitment=graph.cache_request,
        )
        cache_entry = _document(
            cache_row,
            json_key="entry_json",
            sha256_key="document_sha256",
            model_type=ModelCacheEntry,
            commitment=graph.cache,
        )
        try:
            _validate_cache_index(cache_row, cache_request, cache_entry)
        except _IndexFailure:
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        if not _operational_context_is_authorized(
            claim_request,
            cache_request,
            prior_authorities,
        ):
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        caches.append(
            M6M3ModelCacheAuthorityDocument(
                request=cache_request,
                request_document_sha256=graph.cache_request.document_sha256,
                entry=cache_entry,
                document_sha256=graph.cache.document_sha256,
            )
        )
        read_primary.add((graph.cache_request.route, graph.cache_request.rowid))
        read_primary.add((graph.cache.route, graph.cache.rowid))

        receipt_row = _row(connection, _PARSE_RECEIPT_SQL, graph.parse_receipt.rowid)
        parse_receipt = _document(
            receipt_row,
            json_key="receipt_json",
            sha256_key="document_sha256",
            model_type=ModelParseReceipt,
            commitment=graph.parse_receipt,
        )
        _index(_validate_parse_receipt_index, receipt_row, parse_receipt)
        parse_receipts.append(
            M6M3ModelParseReceiptAuthorityDocument(
                receipt=parse_receipt,
                document_sha256=graph.parse_receipt.document_sha256,
            )
        )
        read_primary.add((graph.parse_receipt.route, graph.parse_receipt.rowid))

        if graph.parsed_output is not None:
            output_row = _row(connection, _PARSED_OUTPUT_SQL, graph.parsed_output.rowid)
            output = _document(
                output_row,
                json_key="output_json",
                sha256_key="document_sha256",
                model_type=ParsedScreeningOutput,
                commitment=graph.parsed_output,
            )
            _index(_validate_parsed_output_index, output_row, output)
            parsed_outputs.append(
                M6M3ParsedOutputAuthorityDocument(
                    output=output,
                    document_sha256=graph.parsed_output.document_sha256,
                )
            )
            read_primary.add((graph.parsed_output.route, graph.parsed_output.rowid))

        if graph.usage is None:
            _fail(M6SQLiteM3ModelDocumentFailureCode.PHYSICAL_PLAN_INVALID)
        usage_row = _row(connection, _USAGE_SQL, graph.usage.rowid)
        usage = _document(
            usage_row,
            json_key="usage_json",
            sha256_key="document_sha256",
            model_type=UsageSummary,
            commitment=graph.usage,
        )
        _index(_validate_usage_index, usage_row, usage)
        try:
            usage_document = M6M3ModelUsageAuthorityDocument(
                usage=usage,
                request_id=cast(str, usage_row["request_id"]),
                response_id=cast(str, usage_row["response_id"]),
                case_id=cast(str, usage_row["case_id"]),
                case_revision=cast(int, usage_row["case_revision"]),
                consumer_kind=cast(str, usage_row["consumer_kind"]),
                consumer_id=cast(str, usage_row["consumer_id"]),
                accounted_at=cast(str, usage_row["accounted_at"]),
                document_sha256=graph.usage.document_sha256,
            )
        except (TypeError, ValueError):
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        usages.append(usage_document)
        read_primary.add((graph.usage.route, graph.usage.rowid))

    expected_primary = {(slot.route, slot.rowid) for slot in plan.document_slots} | {
        (value.route, value.rowid) for value in plan.historical_failures
    }
    if read_primary != expected_primary:
        _fail(M6SQLiteM3ModelDocumentFailureCode.PHYSICAL_PLAN_INVALID)

    ordered_usages = tuple(sorted(usages, key=lambda value: value.request_id))
    read_support: set[tuple[M6SQLiteM3SupportDocumentRoute, int]] = set()
    for slot in plan.support_document_slots:
        row = _row(connection, _COMPLETION_SQL, slot.rowid)
        completion_receipt = _document(
            row,
            json_key="receipt_json",
            sha256_key="document_sha256",
            model_type=BacklogCompletionReceipt,
            commitment=slot,
            rowid_key="support_rowid",
        )
        _index(_validate_completion_receipt_index, row, completion_receipt)
        if completion_receipt.receipt_id != slot.artifact_id:
            _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
        _validate_completion_responses(completion_receipt, plan, ordered_usages)
        read_support.add((slot.route, slot.rowid))
    if read_support != {(slot.route, slot.rowid) for slot in plan.support_document_slots}:
        _fail(M6SQLiteM3ModelDocumentFailureCode.PHYSICAL_PLAN_INVALID)

    try:
        snapshot = M6M3ModelCallAuthoritySnapshot(
            source_identity_sha256=plan.plan_identity_sha256,
            run_id=plan.run_id,
            case_id=plan.case_id,
            manifest_id=plan.manifest_id,
            requests=tuple(sorted(request_documents, key=lambda value: value.request.request_id)),
            responses=tuple(sorted(responses, key=lambda value: value.response.response_id)),
            caches=tuple(sorted(caches, key=lambda value: value.entry.cache_entry_id)),
            parse_receipts=tuple(
                sorted(parse_receipts, key=lambda value: value.receipt.parse_receipt_id)
            ),
            parsed_outputs=tuple(
                sorted(parsed_outputs, key=lambda value: value.output.parsed_output_id)
            ),
            failures=tuple(sorted(failures, key=lambda value: value.authority.authority_id)),
            usages=ordered_usages,
            authority_failure_count=0,
        )
    except (TypeError, ValueError):
        _fail(M6SQLiteM3ModelDocumentFailureCode.INDEX_BINDING_MISMATCH)
    _validate_locked_projection(snapshot, plan)
    _active(connection)
    return snapshot


__all__ = ["build_m6_sqlite_m3_model_call_authority_snapshot"]
