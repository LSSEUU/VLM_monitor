"""Canonical document codecs and duplicated-index checks for M3 SQLite rows.

This internal module is deliberately unaware of repository traversal and
cross-table authority.  It reconstructs one row at a time without repairing or
normalizing durable data.
"""

from __future__ import annotations

import hashlib
import re
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import cast

from pydantic import BaseModel, TypeAdapter, ValidationError

from labcourt.contracts.artifact_validation import M3ArtifactInventoryKind
from labcourt.contracts.backlog import BacklogCompletionReceipt, BacklogItem
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import UsageSummary
from labcourt.contracts.enums import ArtifactKind
from labcourt.contracts.model_call_failures import ModelCallFailureAuthority
from labcourt.contracts.references import require_reference_token
from labcourt.contracts.screening import (
    ModelCacheEntry,
    ModelParseReceipt,
    ParsedScreeningOutput,
    ScreeningResult,
    VLMCallRequest,
    VLMRequest,
    VLMResponse,
)
from labcourt.contracts.verdicts import ProceduralDefect, ProceduralReview, Verdict

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_UTC_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
_REQUEST_ADAPTER: TypeAdapter[VLMCallRequest] = TypeAdapter(VLMCallRequest)


@dataclass(frozen=True, slots=True)
class _Record:
    kind: M3ArtifactInventoryKind
    identity: str
    artifact_id: str | None
    row: sqlite3.Row
    document: BaseModel


@dataclass(frozen=True, slots=True)
class _HeadRecord:
    identity: str
    artifact_id: str | None
    row: sqlite3.Row


_DocumentLoader = Callable[[sqlite3.Row], BaseModel]
_IndexValidator = Callable[[sqlite3.Row, BaseModel], None]


class _DocumentFailure(ValueError):
    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class _IndexFailure(ValueError):
    def __init__(self, reason_code: str = "INDEX_BINDING_MISMATCH") -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


def _text(row: sqlite3.Row, key: str) -> str:
    value = row[key]
    if not isinstance(value, str):
        raise _IndexFailure("INDEX_COLUMN_TYPE_INVALID")
    return value


def _integer(row: sqlite3.Row, key: str) -> int:
    value = row[key]
    if not isinstance(value, int) or isinstance(value, bool):
        raise _IndexFailure("INDEX_COLUMN_TYPE_INVALID")
    return value


def _optional_text(row: sqlite3.Row, key: str) -> str | None:
    value = row[key]
    if value is None:
        return None
    if not isinstance(value, str):
        raise _IndexFailure("INDEX_COLUMN_TYPE_INVALID")
    return value


def _float(row: sqlite3.Row, key: str) -> float:
    value = row[key]
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise _IndexFailure("INDEX_COLUMN_TYPE_INVALID")
    return float(value)


def _require_sha256(value: str) -> None:
    if _SHA256.fullmatch(value) is None:
        raise _IndexFailure("INDEX_SHA256_INVALID")


def _require_timestamp(value: str) -> None:
    try:
        parsed = datetime.strptime(value, _UTC_TIMESTAMP_FORMAT).replace(tzinfo=UTC)
    except ValueError:
        raise _IndexFailure("INDEX_TIMESTAMP_INVALID") from None
    if parsed.strftime(_UTC_TIMESTAMP_FORMAT) != value:
        raise _IndexFailure("INDEX_TIMESTAMP_INVALID")


def _canonical_timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise _IndexFailure("INDEX_TIMESTAMP_INVALID")
    return value.astimezone(UTC).strftime(_UTC_TIMESTAMP_FORMAT)


def _record_identity(
    kind: M3ArtifactInventoryKind,
    row: sqlite3.Row,
    keys: tuple[str, ...],
) -> str:
    components: list[object] = []
    for key in keys:
        value = row[key]
        if value is None or isinstance(value, (str, int)):
            components.append(value)
        elif isinstance(value, bytes):
            components.append(
                {
                    "type": "bytes",
                    "sha256": hashlib.sha256(value).hexdigest(),
                }
            )
        else:
            encoded = repr(value).encode("utf-8", errors="backslashreplace")
            components.append(
                {
                    "type": type(value).__name__,
                    "sha256": hashlib.sha256(encoded).hexdigest(),
                }
            )
    payload = canonical_json(["m3-artifact-record", 1, kind.value, components])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _safe_artifact_id(row: sqlite3.Row, key: str) -> str | None:
    value = row[key]
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        return None
    try:
        return require_reference_token(value, "M3 artifact row identity")
    except (TypeError, ValueError):
        return None


def _load_document(
    row: sqlite3.Row,
    *,
    json_key: str,
    sha256_key: str,
    model_type: type[BaseModel],
) -> BaseModel:
    raw = row[json_key]
    expected_sha256 = row[sha256_key]
    if not isinstance(raw, str) or not isinstance(expected_sha256, str):
        raise _DocumentFailure("DOCUMENT_COLUMN_TYPE_INVALID")
    try:
        model = model_type.model_validate_json(raw)
    except (ValidationError, TypeError, ValueError, UnicodeError):
        raise _DocumentFailure("DOCUMENT_CONTRACT_INVALID") from None
    canonical = canonical_json(model.model_dump(mode="json"))
    if raw != canonical:
        raise _DocumentFailure("DOCUMENT_NOT_CANONICAL")
    actual_sha256 = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    if expected_sha256 != actual_sha256:
        raise _DocumentFailure("DOCUMENT_HASH_MISMATCH")
    return model


def _load_request_document(
    row: sqlite3.Row,
    *,
    json_key: str,
    sha256_key: str,
) -> VLMCallRequest:
    raw = row[json_key]
    expected_sha256 = row[sha256_key]
    if not isinstance(raw, str) or not isinstance(expected_sha256, str):
        raise _DocumentFailure("DOCUMENT_COLUMN_TYPE_INVALID")
    try:
        request = _REQUEST_ADAPTER.validate_json(raw)
    except (ValidationError, TypeError, ValueError, UnicodeError):
        raise _DocumentFailure("DOCUMENT_CONTRACT_INVALID") from None
    canonical = canonical_json(request.model_dump(mode="json"))
    if raw != canonical:
        raise _DocumentFailure("DOCUMENT_NOT_CANONICAL")
    if hashlib.sha256(raw.encode("utf-8")).hexdigest() != expected_sha256:
        raise _DocumentFailure("DOCUMENT_HASH_MISMATCH")
    return request


def _same_request_response(request: VLMCallRequest, response: VLMResponse) -> bool:
    expected_attempt = 0 if isinstance(request, VLMRequest) else 1
    return (
        request.run_id == response.run_id
        and request.case_id == response.case_id
        and request.evidence_pack_id == response.evidence_pack_id
        and request.evidence_pack_version == response.evidence_pack_version
        and request.request_id == response.request_id
        and request.request_sha256 == response.request_sha256
        and request.cache_key == response.cache_key
        and request.purpose == response.purpose
        and response.attempt_index == expected_attempt
        and request.model_manifest_id == response.model_manifest_id
        and request.manifest_id == response.manifest_id
    )


def _same_semantic_request(left: VLMCallRequest, right: VLMCallRequest) -> bool:
    """Ignore queue provenance while retaining every semantic generation input."""

    return type(left) is type(right) and left.request_projection() == right.request_projection()


def _operational_context_is_authorized(
    claim_request: VLMCallRequest,
    observed_request: VLMCallRequest,
    authorities: list[ModelCallFailureAuthority],
) -> bool:
    if claim_request == observed_request:
        return True
    context = observed_request.backlog_retry_context
    return (
        context is not None
        and _same_semantic_request(claim_request, observed_request)
        and any(
            authority.backlog_item_id == context.backlog_item_id
            and authority.retry_generation == context.retry_generation
            and _same_semantic_request(authority.request, observed_request)
            for authority in authorities
        )
    )


def _same_backlog_identity(left: BacklogItem, right: BacklogItem) -> bool:
    return (
        left.item_id == right.item_id
        and left.run_id == right.run_id
        and left.case_id == right.case_id
        and left.stage == right.stage
        and left.role == right.role
        and left.reason_code == right.reason_code
        and left.stage_input_ref == right.stage_input_ref
        and left.stage_input_sha256 == right.stage_input_sha256
        and left.max_attempts == right.max_attempts
        and left.manifest_id == right.manifest_id
    )


def _validate_claim_index(row: sqlite3.Row, document: BaseModel) -> None:
    request = cast(VLMCallRequest, document)
    indexed = (
        _text(row, "run_id"),
        _text(row, "request_id"),
        _text(row, "request_sha256"),
        _text(row, "cache_key"),
        _text(row, "case_id"),
        _text(row, "evidence_pack_id"),
        _integer(row, "evidence_pack_version"),
        _text(row, "purpose"),
        _text(row, "model_manifest_id"),
        _text(row, "manifest_id"),
    )
    expected = (
        request.run_id,
        request.request_id,
        request.request_sha256,
        request.cache_key,
        request.case_id,
        request.evidence_pack_id,
        request.evidence_pack_version,
        request.purpose.value,
        request.model_manifest_id,
        request.manifest_id,
    )
    if indexed != expected:
        raise _IndexFailure()
    owner = _text(row, "owner_token_sha256")
    _require_sha256(owner)
    _require_timestamp(_text(row, "lease_expires_at"))
    _require_timestamp(_text(row, "created_at"))
    takeover_count = _integer(row, "takeover_count")
    if takeover_count < 0:
        raise _IndexFailure()
    status = _text(row, "status")
    response_id = _optional_text(row, "response_id")
    completed_at = _optional_text(row, "completed_at")
    if status == "ACTIVE":
        if response_id is not None or completed_at is not None:
            raise _IndexFailure()
        return
    if status != "COMPLETED" or response_id is None or completed_at is None:
        raise _IndexFailure()
    _require_sha256(response_id)
    _require_timestamp(completed_at)


def _validate_failure_authority_index(row: sqlite3.Row, document: BaseModel) -> None:
    authority = cast(ModelCallFailureAuthority, document)
    indexed = (
        _text(row, "run_id"),
        _text(row, "authority_id"),
        _text(row, "request_id"),
        _text(row, "request_sha256"),
        _text(row, "request_document_sha256"),
        _text(row, "cache_key"),
        _text(row, "case_id"),
        _text(row, "evidence_pack_id"),
        _integer(row, "evidence_pack_version"),
        _text(row, "purpose"),
        _text(row, "model_manifest_id"),
        _text(row, "claim_owner_sha256"),
        _text(row, "claim_lease_expires_at"),
        _integer(row, "claim_takeover_count"),
        _text(row, "failure_code"),
        _text(row, "delivery_certainty"),
        _text(row, "backlog_reason_code"),
        _text(row, "backlog_item_id"),
        _integer(row, "backlog_version"),
        _text(row, "backlog_status"),
        _integer(row, "backlog_attempt_count"),
        _integer(row, "retry_generation"),
        _text(row, "closure_kind"),
        _optional_text(row, "completion_receipt_id"),
        _integer(row, "closure_case_revision"),
        _integer(row, "closure_audit_sequence"),
        _text(row, "closure_audit_entry_hash"),
        _text(row, "manifest_id"),
        _text(row, "recorded_at"),
    )
    expected = (
        authority.run_id,
        authority.authority_id,
        authority.request.request_id,
        authority.request.request_sha256,
        authority.request_document_sha256,
        authority.request.cache_key,
        authority.request.case_id,
        authority.request.evidence_pack_id,
        authority.request.evidence_pack_version,
        authority.request.purpose.value,
        authority.request.model_manifest_id,
        authority.claim_owner_sha256,
        _canonical_timestamp(authority.claim_lease_expires_at),
        authority.claim_takeover_count,
        authority.failure_code.value,
        authority.delivery_certainty.value,
        authority.backlog_reason_code.value,
        authority.backlog_item_id,
        authority.backlog_version,
        authority.backlog_status.value,
        authority.backlog_attempt_count,
        authority.retry_generation,
        authority.closure_kind.value,
        authority.completion_receipt_id,
        authority.closure_case_revision,
        authority.closure_audit_sequence,
        authority.closure_audit_entry_hash,
        authority.manifest_id,
        _canonical_timestamp(authority.recorded_at),
    )
    if indexed != expected:
        raise _IndexFailure()
    _require_sha256(authority.claim_owner_sha256)
    _require_timestamp(_text(row, "claim_lease_expires_at"))
    _require_timestamp(_text(row, "recorded_at"))


def _validate_response_index(row: sqlite3.Row, document: BaseModel) -> None:
    response = cast(VLMResponse, document)
    indexed = (
        _text(row, "run_id"),
        _text(row, "response_id"),
        _text(row, "case_id"),
        _text(row, "evidence_pack_id"),
        _integer(row, "evidence_pack_version"),
        _text(row, "request_id"),
        _text(row, "request_sha256"),
        _text(row, "cache_key"),
        _text(row, "purpose"),
        _integer(row, "attempt_index"),
        _text(row, "raw_response_ref"),
        _text(row, "content_sha256"),
        _integer(row, "size_bytes"),
        _text(row, "model_manifest_id"),
        _text(row, "manifest_id"),
    )
    expected = (
        response.run_id,
        response.response_id,
        response.case_id,
        response.evidence_pack_id,
        response.evidence_pack_version,
        response.request_id,
        response.request_sha256,
        response.cache_key,
        response.purpose.value,
        response.attempt_index,
        response.raw_response_ref,
        response.content_sha256,
        response.size_bytes,
        response.model_manifest_id,
        response.manifest_id,
    )
    if indexed != expected:
        raise _IndexFailure()


def _validate_parsed_output_index(row: sqlite3.Row, document: BaseModel) -> None:
    output = cast(ParsedScreeningOutput, document)
    indexed = (
        _text(row, "run_id"),
        _text(row, "parsed_output_id"),
        _text(row, "case_id"),
        _text(row, "evidence_pack_id"),
        _integer(row, "evidence_pack_version"),
        _text(row, "request_id"),
        _text(row, "response_id"),
        _text(row, "response_content_sha256"),
        _text(row, "output_schema_sha256"),
        _text(row, "model_payload_sha256"),
        _text(row, "parsed_output_sha256"),
        _text(row, "manifest_id"),
    )
    expected = (
        output.run_id,
        output.parsed_output_id,
        output.case_id,
        output.evidence_pack_id,
        output.evidence_pack_version,
        output.request_id,
        output.response_id,
        output.response_content_sha256,
        output.output_schema_sha256,
        output.model_payload_sha256,
        output.parsed_output_sha256,
        output.manifest_id,
    )
    if indexed != expected:
        raise _IndexFailure()


def _validate_parse_receipt_index(row: sqlite3.Row, document: BaseModel) -> None:
    receipt = cast(ModelParseReceipt, document)
    indexed = (
        _text(row, "run_id"),
        _text(row, "parse_receipt_id"),
        _text(row, "case_id"),
        _text(row, "evidence_pack_id"),
        _integer(row, "evidence_pack_version"),
        _text(row, "request_id"),
        _text(row, "response_id"),
        _integer(row, "attempt_index"),
        _text(row, "status"),
        _optional_text(row, "parsed_output_id"),
        _optional_text(row, "parsed_output_sha256"),
        _optional_text(row, "repair_request_id"),
        _text(row, "manifest_id"),
    )
    expected = (
        receipt.run_id,
        receipt.parse_receipt_id,
        receipt.case_id,
        receipt.evidence_pack_id,
        receipt.evidence_pack_version,
        receipt.request_id,
        receipt.response_id,
        receipt.attempt_index,
        receipt.status.value,
        receipt.parsed_output_id,
        receipt.parsed_output_sha256,
        receipt.repair_request_id,
        receipt.manifest_id,
    )
    if indexed != expected:
        raise _IndexFailure()


def _validate_cache_index(
    row: sqlite3.Row,
    request: VLMCallRequest,
    entry: ModelCacheEntry,
) -> None:
    indexed = (
        _text(row, "run_id"),
        _text(row, "cache_key"),
        _text(row, "cache_entry_id"),
        _text(row, "case_id"),
        _text(row, "evidence_pack_id"),
        _integer(row, "evidence_pack_version"),
        _text(row, "request_id"),
        _text(row, "request_sha256"),
        _text(row, "response_id"),
        _text(row, "response_content_sha256"),
        _text(row, "model_manifest_id"),
        _text(row, "prompt_manifest_id"),
        _text(row, "output_schema_sha256"),
        _text(row, "manifest_id"),
    )
    expected_entry = (
        entry.run_id,
        entry.cache_key,
        entry.cache_entry_id,
        entry.case_id,
        entry.evidence_pack_id,
        entry.evidence_pack_version,
        entry.request_id,
        entry.request_sha256,
        entry.response_id,
        entry.response_content_sha256,
        entry.model_manifest_id,
        entry.prompt_manifest_id,
        entry.output_schema_sha256,
        entry.manifest_id,
    )
    expected_request = (
        request.run_id,
        request.cache_key,
        entry.cache_entry_id,
        request.case_id,
        request.evidence_pack_id,
        request.evidence_pack_version,
        request.request_id,
        request.request_sha256,
        entry.response_id,
        entry.response_content_sha256,
        request.model_manifest_id,
        request.prompt_manifest.prompt_manifest_id,
        request.prompt_manifest.output_schema_sha256,
        request.manifest_id,
    )
    if indexed != expected_entry or indexed != expected_request:
        raise _IndexFailure()


def _validate_usage_index(row: sqlite3.Row, document: BaseModel) -> None:
    usage = cast(UsageSummary, document)
    indexed = (
        _integer(row, "input_images"),
        _integer(row, "input_pixels"),
        _integer(row, "input_tokens"),
        _integer(row, "output_tokens"),
        _integer(row, "provider_latency_ms"),
        _integer(row, "retries"),
        _float(row, "estimated_cost"),
    )
    expected = (
        usage.input_images,
        usage.input_pixels,
        usage.input_tokens,
        usage.output_tokens,
        usage.provider_latency_ms,
        usage.retries,
        usage.estimated_cost,
    )
    if indexed != expected:
        raise _IndexFailure()
    _require_sha256(_text(row, "request_id"))
    _require_sha256(_text(row, "response_id"))
    _require_sha256(_text(row, "consumer_id"))
    _require_timestamp(_text(row, "accounted_at"))
    if _integer(row, "case_revision") <= 0:
        raise _IndexFailure()
    if _text(row, "consumer_kind") not in {
        ArtifactKind.SCREENING_RESULT.value,
        ArtifactKind.BACKLOG_ITEM.value,
    }:
        raise _IndexFailure()


def _validate_screening_index(row: sqlite3.Row, document: BaseModel) -> None:
    screening = cast(ScreeningResult, document)
    indexed = (
        _text(row, "run_id"),
        _text(row, "screening_id"),
        _text(row, "case_id"),
        _integer(row, "version"),
        _text(row, "evidence_pack_id"),
        _integer(row, "evidence_pack_version"),
        _text(row, "parsed_output_id"),
        _text(row, "decision"),
        _text(row, "manifest_id"),
    )
    expected = (
        screening.run_id,
        screening.screening_id,
        screening.case_id,
        screening.version,
        screening.evidence_pack_id,
        screening.evidence_pack_version,
        screening.parsed_output.parsed_output_id,
        screening.decision.value,
        screening.manifest_id,
    )
    if indexed != expected or _integer(row, "audit_sequence") < 0:
        raise _IndexFailure()


def _validate_verdict_index(row: sqlite3.Row, document: BaseModel) -> None:
    verdict = cast(Verdict, document)
    indexed = (
        _text(row, "run_id"),
        _text(row, "verdict_id"),
        _text(row, "case_id"),
        _integer(row, "version"),
        _text(row, "screening_id"),
        _text(row, "evidence_pack_id"),
        _integer(row, "evidence_pack_version"),
        _text(row, "verdict_input_sha256"),
        _text(row, "verdict_sha256"),
        _text(row, "manifest_id"),
    )
    expected = (
        verdict.run_id,
        verdict.verdict_id,
        verdict.case_id,
        verdict.version,
        verdict.screening_id,
        verdict.evidence_pack_id,
        verdict.evidence_pack_version,
        verdict.verdict_input_sha256,
        verdict.verdict_sha256,
        verdict.manifest_id,
    )
    if indexed != expected or _integer(row, "audit_sequence") < 0:
        raise _IndexFailure()


def _validate_review_index(row: sqlite3.Row, document: BaseModel) -> None:
    review = cast(ProceduralReview, document)
    indexed = (
        _text(row, "run_id"),
        _text(row, "review_id"),
        _text(row, "case_id"),
        _integer(row, "version"),
        _text(row, "evidence_pack_id"),
        _integer(row, "evidence_pack_version"),
        _text(row, "reviewed_verdict_id"),
        _integer(row, "reviewed_verdict_version"),
        _text(row, "reviewed_verdict_sha256"),
        _integer(row, "passed"),
        _text(row, "manifest_id"),
    )
    expected = (
        review.run_id,
        review.review_id,
        review.case_id,
        review.version,
        review.evidence_pack_id,
        review.evidence_pack_version,
        review.reviewed_verdict_id,
        review.reviewed_verdict_version,
        review.reviewed_verdict_sha256,
        int(review.passed),
        review.manifest_id,
    )
    if indexed != expected or _integer(row, "audit_sequence") < 0:
        raise _IndexFailure()


def _validate_defect_index(row: sqlite3.Row, document: BaseModel) -> None:
    defect = cast(ProceduralDefect, document)
    owner_kind = _text(row, "owner_kind")
    owner_id = _text(row, "owner_id")
    parse_receipt_id = _optional_text(row, "parse_receipt_id")
    review_id = _optional_text(row, "review_id")
    indexed = (
        _text(row, "run_id"),
        owner_kind,
        owner_id,
        _integer(row, "ordinal"),
        _text(row, "defect_id"),
        _text(row, "origin"),
        _text(row, "code"),
        _text(row, "artifact_kind"),
        _text(row, "artifact_id"),
    )
    if indexed[3] < 0 or indexed[4:] != (
        defect.defect_id,
        defect.origin.value,
        defect.code.value,
        defect.artifact_ref.kind.value,
        defect.artifact_ref.artifact_id,
    ):
        raise _IndexFailure()
    if indexed[0] == "" or owner_id == "":
        raise _IndexFailure()
    if owner_kind == ArtifactKind.MODEL_PARSE_RECEIPT.value:
        if (
            parse_receipt_id != owner_id
            or review_id is not None
            or defect.artifact_ref.kind != ArtifactKind.MODEL_RESPONSE
        ):
            raise _IndexFailure()
    elif owner_kind == ArtifactKind.PROCEDURAL_REVIEW.value:
        if (
            review_id != owner_id
            or parse_receipt_id is not None
            or defect.artifact_ref.kind != ArtifactKind.VERDICT
        ):
            raise _IndexFailure()
    else:
        raise _IndexFailure()


def _validate_backlog_identity_index(row: sqlite3.Row, document: BaseModel) -> None:
    item = cast(BacklogItem, document)
    indexed = (
        _text(row, "run_id"),
        _text(row, "item_id"),
        _text(row, "case_id"),
        _text(row, "stage"),
        _optional_text(row, "role"),
        _text(row, "reason_code"),
        _text(row, "stage_input_kind"),
        _text(row, "stage_input_id"),
        _text(row, "stage_input_sha256"),
        _integer(row, "max_attempts"),
        _text(row, "manifest_id"),
    )
    expected = (
        item.run_id,
        item.item_id,
        item.case_id,
        item.stage.value,
        item.role.value if item.role is not None else None,
        item.reason_code.value,
        item.stage_input_ref.kind.value,
        item.stage_input_ref.artifact_id,
        item.stage_input_sha256,
        item.max_attempts,
        item.manifest_id,
    )
    if indexed != expected:
        raise _IndexFailure()


def _validate_backlog_version_index(row: sqlite3.Row, document: BaseModel) -> None:
    item = cast(BacklogItem, document)
    indexed = (
        _text(row, "run_id"),
        _text(row, "item_id"),
        _text(row, "status"),
        _integer(row, "attempt_count"),
        _integer(row, "retry_generation"),
        _optional_text(row, "lease_id"),
        _optional_text(row, "lease_owner_sha256"),
        _optional_text(row, "lease_expires_at"),
    )
    expected = (
        item.run_id,
        item.item_id,
        item.status.value,
        item.attempt_count,
        item.retry_generation,
        item.lease_id,
        item.lease_owner_sha256,
        _canonical_timestamp(item.lease_expires_at) if item.lease_expires_at is not None else None,
    )
    if indexed != expected or _integer(row, "version") <= 0:
        raise _IndexFailure()


def _validate_completion_receipt_index(row: sqlite3.Row, document: BaseModel) -> None:
    receipt = cast(BacklogCompletionReceipt, document)
    outcome = receipt.outcome
    indexed = (
        _text(row, "run_id"),
        _text(row, "receipt_id"),
        _text(row, "item_id"),
        _text(row, "outcome_kind"),
        _text(row, "outcome_id"),
        _text(row, "lease_identity_sha256"),
        _text(row, "lease_id"),
        _integer(row, "attempt_count"),
        _integer(row, "retry_generation"),
        _text(row, "backlog_status"),
        _text(row, "completion_kind"),
        _text(row, "completion_id"),
        _text(row, "completion_case_status"),
        _integer(row, "completion_case_revision"),
        _integer(row, "completion_audit_sequence"),
        _text(row, "completion_audit_entry_hash"),
        _text(row, "manifest_id"),
    )
    expected = (
        outcome.lease.run_id,
        receipt.receipt_id,
        outcome.lease.item_id,
        outcome.outcome_kind,
        outcome.outcome_id,
        outcome.lease.lease_identity_sha256,
        outcome.lease.lease_id,
        outcome.lease.attempt_count,
        outcome.lease.retry_generation,
        receipt.backlog_status.value,
        receipt.completion_ref.kind.value,
        receipt.completion_ref.artifact_id,
        receipt.completion_case_status.value,
        receipt.completion_case_revision,
        receipt.completion_audit_sequence,
        receipt.completion_audit_entry_hash,
        receipt.manifest_id,
    )
    if indexed != expected or _integer(row, "backlog_version") <= 0:
        raise _IndexFailure()
