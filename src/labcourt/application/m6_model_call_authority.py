"""Assemble exact M3 screening-call inputs for M6 locked replay."""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import NoReturn, TypeVar

from pydantic import TypeAdapter, ValidationError

from labcourt.contracts.base import FrozenContractModel
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case, UsageSummary
from labcourt.contracts.enums import ModelParseStatus
from labcourt.contracts.m6_replay_locked import (
    MAX_M6_LOCKED_MODEL_CALLS_PER_CASE,
    M6LockedModelCallInput,
    M6LockedModelCallLayer,
    M6LockedModelCallResultKind,
    M6LockedModelRole,
    M6ReplayAuthorityKind,
    M6ReplayAuthorityRef,
)
from labcourt.contracts.model_call_failures import ModelCallFailureAuthority
from labcourt.contracts.screening import (
    CachedModelResponse,
    ModelCacheEntry,
    ModelParseReceipt,
    ParsedScreeningOutput,
    StructureRepairRequest,
    VLMCallRequest,
    VLMRequest,
    VLMResponse,
)
from labcourt.domain.m6_semantic_projection import resolve_m6_locked_model_responses
from labcourt.exceptions import LabCourtError
from labcourt.ports.m6_model_calls import (
    M6M3ModelCallAuthoritySnapshot,
    M6M3ModelRequestAuthorityDocument,
    M6M3ModelUsageAuthorityDocument,
)

_ModelT = TypeVar("_ModelT", bound=FrozenContractModel)
_REQUEST_ADAPTER: TypeAdapter[VLMCallRequest] = TypeAdapter(VLMCallRequest)


class M6ModelCallAuthorityErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    SNAPSHOT_AUTHORITY_INVALID = "SNAPSHOT_AUTHORITY_INVALID"
    SNAPSHOT_SCOPE_MISMATCH = "SNAPSHOT_SCOPE_MISMATCH"
    SOURCE_CASE_INVALID = "SOURCE_CASE_INVALID"
    MODEL_REQUEST_DOCUMENT_INVALID = "MODEL_REQUEST_DOCUMENT_INVALID"
    MODEL_REQUEST_DUPLICATE = "MODEL_REQUEST_DUPLICATE"
    MODEL_REQUEST_UNSTABLE = "MODEL_REQUEST_UNSTABLE"
    MODEL_REQUEST_SCOPE_MISMATCH = "MODEL_REQUEST_SCOPE_MISMATCH"
    MODEL_REQUEST_PACK_MISMATCH = "MODEL_REQUEST_PACK_MISMATCH"
    MODEL_RESPONSE_DOCUMENT_INVALID = "MODEL_RESPONSE_DOCUMENT_INVALID"
    MODEL_RESPONSE_DUPLICATE = "MODEL_RESPONSE_DUPLICATE"
    MODEL_RESPONSE_UNSTABLE = "MODEL_RESPONSE_UNSTABLE"
    MODEL_RESPONSE_SCOPE_MISMATCH = "MODEL_RESPONSE_SCOPE_MISMATCH"
    MODEL_RESPONSE_MISSING = "MODEL_RESPONSE_MISSING"
    MODEL_RESPONSE_EXTRA = "MODEL_RESPONSE_EXTRA"
    MODEL_RESPONSE_BINDING_MISMATCH = "MODEL_RESPONSE_BINDING_MISMATCH"
    MODEL_CACHE_DOCUMENT_INVALID = "MODEL_CACHE_DOCUMENT_INVALID"
    MODEL_CACHE_DUPLICATE = "MODEL_CACHE_DUPLICATE"
    MODEL_CACHE_UNSTABLE = "MODEL_CACHE_UNSTABLE"
    MODEL_CACHE_SCOPE_MISMATCH = "MODEL_CACHE_SCOPE_MISMATCH"
    MODEL_CACHE_MISSING = "MODEL_CACHE_MISSING"
    MODEL_CACHE_EXTRA = "MODEL_CACHE_EXTRA"
    MODEL_CACHE_BINDING_MISMATCH = "MODEL_CACHE_BINDING_MISMATCH"
    PARSE_RECEIPT_DOCUMENT_INVALID = "PARSE_RECEIPT_DOCUMENT_INVALID"
    PARSE_RECEIPT_DUPLICATE = "PARSE_RECEIPT_DUPLICATE"
    PARSE_RECEIPT_UNSTABLE = "PARSE_RECEIPT_UNSTABLE"
    PARSE_RECEIPT_SCOPE_MISMATCH = "PARSE_RECEIPT_SCOPE_MISMATCH"
    PARSE_RECEIPT_MISSING = "PARSE_RECEIPT_MISSING"
    PARSE_RECEIPT_EXTRA = "PARSE_RECEIPT_EXTRA"
    PARSE_RECEIPT_BINDING_MISMATCH = "PARSE_RECEIPT_BINDING_MISMATCH"
    PARSED_OUTPUT_DOCUMENT_INVALID = "PARSED_OUTPUT_DOCUMENT_INVALID"
    PARSED_OUTPUT_DUPLICATE = "PARSED_OUTPUT_DUPLICATE"
    PARSED_OUTPUT_UNSTABLE = "PARSED_OUTPUT_UNSTABLE"
    PARSED_OUTPUT_SCOPE_MISMATCH = "PARSED_OUTPUT_SCOPE_MISMATCH"
    PARSED_OUTPUT_MISSING = "PARSED_OUTPUT_MISSING"
    PARSED_OUTPUT_EXTRA = "PARSED_OUTPUT_EXTRA"
    PARSED_OUTPUT_BINDING_MISMATCH = "PARSED_OUTPUT_BINDING_MISMATCH"
    MODEL_FAILURE_DOCUMENT_INVALID = "MODEL_FAILURE_DOCUMENT_INVALID"
    MODEL_FAILURE_DUPLICATE = "MODEL_FAILURE_DUPLICATE"
    MODEL_FAILURE_UNSTABLE = "MODEL_FAILURE_UNSTABLE"
    MODEL_FAILURE_SCOPE_MISMATCH = "MODEL_FAILURE_SCOPE_MISMATCH"
    MODEL_FAILURE_EXTRA = "MODEL_FAILURE_EXTRA"
    MODEL_FAILURE_BINDING_MISMATCH = "MODEL_FAILURE_BINDING_MISMATCH"
    MODEL_USAGE_DOCUMENT_INVALID = "MODEL_USAGE_DOCUMENT_INVALID"
    MODEL_USAGE_DUPLICATE = "MODEL_USAGE_DUPLICATE"
    MODEL_USAGE_UNSTABLE = "MODEL_USAGE_UNSTABLE"
    MODEL_USAGE_SCOPE_MISMATCH = "MODEL_USAGE_SCOPE_MISMATCH"
    MODEL_USAGE_MISSING = "MODEL_USAGE_MISSING"
    MODEL_USAGE_EXTRA = "MODEL_USAGE_EXTRA"
    MODEL_USAGE_BINDING_MISMATCH = "MODEL_USAGE_BINDING_MISMATCH"
    MODEL_CALL_RESULT_MISSING = "MODEL_CALL_RESULT_MISSING"
    MODEL_CALL_RESULT_CROSSED = "MODEL_CALL_RESULT_CROSSED"
    MODEL_CALL_BUDGET_EXCEEDED = "MODEL_CALL_BUDGET_EXCEEDED"
    REPAIR_HISTORY_INVALID = "REPAIR_HISTORY_INVALID"
    LOCKED_MODEL_CALL_INVALID = "LOCKED_MODEL_CALL_INVALID"
    RESOLVED_MODEL_RESPONSE_INVALID = "RESOLVED_MODEL_RESPONSE_INVALID"


class M6ModelCallAuthorityError(LabCourtError):
    """One M3 authority graph cannot produce an exact locked call inventory."""

    def __init__(self, code: M6ModelCallAuthorityErrorCode) -> None:
        if not isinstance(code, M6ModelCallAuthorityErrorCode):
            raise TypeError("code must be an M6ModelCallAuthorityErrorCode")
        self.code = code
        super().__init__(f"M6 model-call authority failed: {code.value}")


def _fail(code: M6ModelCallAuthorityErrorCode) -> NoReturn:
    raise M6ModelCallAuthorityError(code)


def _document_sha256(document: FrozenContractModel) -> str:
    raw = canonical_json(document.model_dump(mode="json"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _canonical_document(
    value: object,
    model_type: type[_ModelT],
    claimed_sha256: str,
    failure: M6ModelCallAuthorityErrorCode,
) -> _ModelT:
    if not isinstance(value, model_type):
        _fail(failure)
    try:
        controlled = model_type.model_validate(
            value.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (TypeError, ValueError, ValidationError):
        _fail(failure)
    if controlled != value or _document_sha256(controlled) != claimed_sha256:
        _fail(failure)
    return controlled


def _canonical_request(
    document: M6M3ModelRequestAuthorityDocument,
    *,
    claimed_sha256: str | None = None,
    failure: M6ModelCallAuthorityErrorCode = (
        M6ModelCallAuthorityErrorCode.MODEL_REQUEST_DOCUMENT_INVALID
    ),
) -> VLMCallRequest:
    try:
        controlled = _REQUEST_ADAPTER.validate_python(
            document.request.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(failure)
    if controlled != document.request or _document_sha256(controlled) != (
        claimed_sha256 if claimed_sha256 is not None else document.document_sha256
    ):
        _fail(failure)
    return controlled


def _require_stable_unique(
    keys: tuple[str, ...],
    *,
    duplicate: M6ModelCallAuthorityErrorCode,
    unstable: M6ModelCallAuthorityErrorCode,
) -> None:
    if len(keys) != len(set(keys)):
        _fail(duplicate)
    if keys != tuple(sorted(keys)):
        _fail(unstable)


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
    return type(left) is type(right) and left.request_projection() == right.request_projection()


def _expected_usage(request: VLMCallRequest, response: VLMResponse) -> UsageSummary:
    return UsageSummary(
        input_images=len(request.media) if isinstance(request, VLMRequest) else 0,
        input_pixels=(
            sum(item.width * item.height for item in request.media)
            if isinstance(request, VLMRequest)
            else 0
        ),
        input_tokens=response.input_tokens,
        output_tokens=response.output_tokens,
        provider_latency_ms=response.latency_ms,
        retries=response.attempt_index,
        estimated_cost=request.budget.estimate_cost(
            input_tokens=response.input_tokens,
            output_tokens=response.output_tokens,
        ),
    )


def _scope_matches(
    document: VLMCallRequest
    | VLMResponse
    | ModelCacheEntry
    | ModelParseReceipt
    | ParsedScreeningOutput,
    source_case: Case,
) -> bool:
    return (
        document.run_id == source_case.run_id
        and document.case_id == source_case.case_id
        and document.manifest_id == source_case.manifest_id
    )


def _validated_arguments(
    source_case: object,
    snapshot: object,
) -> tuple[Case, M6M3ModelCallAuthoritySnapshot]:
    if not isinstance(source_case, Case) or not isinstance(
        snapshot,
        M6M3ModelCallAuthoritySnapshot,
    ):
        _fail(M6ModelCallAuthorityErrorCode.INVALID_ARGUMENT)
    try:
        controlled_case = Case.model_validate(
            source_case.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (TypeError, ValueError, ValidationError):
        _fail(M6ModelCallAuthorityErrorCode.SOURCE_CASE_INVALID)
    if controlled_case != source_case:
        _fail(M6ModelCallAuthorityErrorCode.SOURCE_CASE_INVALID)
    if snapshot.authority_failure_count != 0:
        _fail(M6ModelCallAuthorityErrorCode.SNAPSHOT_AUTHORITY_INVALID)
    if (
        snapshot.run_id != controlled_case.run_id
        or snapshot.case_id != controlled_case.case_id
        or snapshot.manifest_id != controlled_case.manifest_id
    ):
        _fail(M6ModelCallAuthorityErrorCode.SNAPSHOT_SCOPE_MISMATCH)
    if any(
        len(values) > MAX_M6_LOCKED_MODEL_CALLS_PER_CASE
        for values in (
            snapshot.requests,
            snapshot.responses,
            snapshot.caches,
            snapshot.parse_receipts,
            snapshot.parsed_outputs,
            snapshot.failures,
            snapshot.usages,
        )
    ):
        _fail(M6ModelCallAuthorityErrorCode.MODEL_CALL_BUDGET_EXCEEDED)
    return controlled_case, snapshot


def _validated_requests(
    source_case: Case,
    snapshot: M6M3ModelCallAuthoritySnapshot,
) -> tuple[VLMCallRequest, ...]:
    requests = tuple(_canonical_request(document) for document in snapshot.requests)
    _require_stable_unique(
        tuple(request.request_id for request in requests),
        duplicate=M6ModelCallAuthorityErrorCode.MODEL_REQUEST_DUPLICATE,
        unstable=M6ModelCallAuthorityErrorCode.MODEL_REQUEST_UNSTABLE,
    )
    pack_keys = {(pack.pack_id, pack.version) for pack in source_case.evidence_packs}
    for request in requests:
        if not _scope_matches(request, source_case):
            _fail(M6ModelCallAuthorityErrorCode.MODEL_REQUEST_SCOPE_MISMATCH)
        if (request.evidence_pack_id, request.evidence_pack_version) not in pack_keys:
            _fail(M6ModelCallAuthorityErrorCode.MODEL_REQUEST_PACK_MISMATCH)
    return requests


def _validated_responses(
    source_case: Case,
    snapshot: M6M3ModelCallAuthoritySnapshot,
) -> tuple[VLMResponse, ...]:
    responses = tuple(
        _canonical_document(
            document.response,
            VLMResponse,
            document.document_sha256,
            M6ModelCallAuthorityErrorCode.MODEL_RESPONSE_DOCUMENT_INVALID,
        )
        for document in snapshot.responses
    )
    _require_stable_unique(
        tuple(response.response_id for response in responses),
        duplicate=M6ModelCallAuthorityErrorCode.MODEL_RESPONSE_DUPLICATE,
        unstable=M6ModelCallAuthorityErrorCode.MODEL_RESPONSE_UNSTABLE,
    )
    if any(not _scope_matches(response, source_case) for response in responses):
        _fail(M6ModelCallAuthorityErrorCode.MODEL_RESPONSE_SCOPE_MISMATCH)
    return responses


def _validated_caches(
    source_case: Case,
    snapshot: M6M3ModelCallAuthoritySnapshot,
) -> tuple[tuple[VLMCallRequest, ModelCacheEntry], ...]:
    values: list[tuple[VLMCallRequest, ModelCacheEntry]] = []
    for document in snapshot.caches:
        request_document = M6M3ModelRequestAuthorityDocument(
            request=document.request,
            document_sha256=document.request_document_sha256,
        )
        request = _canonical_request(
            request_document,
            failure=M6ModelCallAuthorityErrorCode.MODEL_CACHE_DOCUMENT_INVALID,
        )
        entry = _canonical_document(
            document.entry,
            ModelCacheEntry,
            document.document_sha256,
            M6ModelCallAuthorityErrorCode.MODEL_CACHE_DOCUMENT_INVALID,
        )
        if not _scope_matches(request, source_case) or not _scope_matches(entry, source_case):
            _fail(M6ModelCallAuthorityErrorCode.MODEL_CACHE_SCOPE_MISMATCH)
        values.append((request, entry))
    controlled = tuple(values)
    _require_stable_unique(
        tuple(entry.cache_entry_id for _request, entry in controlled),
        duplicate=M6ModelCallAuthorityErrorCode.MODEL_CACHE_DUPLICATE,
        unstable=M6ModelCallAuthorityErrorCode.MODEL_CACHE_UNSTABLE,
    )
    return controlled


def _validated_receipts(
    source_case: Case,
    snapshot: M6M3ModelCallAuthoritySnapshot,
) -> tuple[ModelParseReceipt, ...]:
    receipts = tuple(
        _canonical_document(
            document.receipt,
            ModelParseReceipt,
            document.document_sha256,
            M6ModelCallAuthorityErrorCode.PARSE_RECEIPT_DOCUMENT_INVALID,
        )
        for document in snapshot.parse_receipts
    )
    _require_stable_unique(
        tuple(receipt.parse_receipt_id for receipt in receipts),
        duplicate=M6ModelCallAuthorityErrorCode.PARSE_RECEIPT_DUPLICATE,
        unstable=M6ModelCallAuthorityErrorCode.PARSE_RECEIPT_UNSTABLE,
    )
    if any(not _scope_matches(receipt, source_case) for receipt in receipts):
        _fail(M6ModelCallAuthorityErrorCode.PARSE_RECEIPT_SCOPE_MISMATCH)
    return receipts


def _validated_outputs(
    source_case: Case,
    snapshot: M6M3ModelCallAuthoritySnapshot,
) -> tuple[ParsedScreeningOutput, ...]:
    outputs = tuple(
        _canonical_document(
            document.output,
            ParsedScreeningOutput,
            document.document_sha256,
            M6ModelCallAuthorityErrorCode.PARSED_OUTPUT_DOCUMENT_INVALID,
        )
        for document in snapshot.parsed_outputs
    )
    _require_stable_unique(
        tuple(output.parsed_output_id for output in outputs),
        duplicate=M6ModelCallAuthorityErrorCode.PARSED_OUTPUT_DUPLICATE,
        unstable=M6ModelCallAuthorityErrorCode.PARSED_OUTPUT_UNSTABLE,
    )
    if any(not _scope_matches(output, source_case) for output in outputs):
        _fail(M6ModelCallAuthorityErrorCode.PARSED_OUTPUT_SCOPE_MISMATCH)
    return outputs


def _validated_failures(
    source_case: Case,
    snapshot: M6M3ModelCallAuthoritySnapshot,
) -> tuple[ModelCallFailureAuthority, ...]:
    failures = tuple(
        _canonical_document(
            document.authority,
            ModelCallFailureAuthority,
            document.document_sha256,
            M6ModelCallAuthorityErrorCode.MODEL_FAILURE_DOCUMENT_INVALID,
        )
        for document in snapshot.failures
    )
    _require_stable_unique(
        tuple(authority.authority_id for authority in failures),
        duplicate=M6ModelCallAuthorityErrorCode.MODEL_FAILURE_DUPLICATE,
        unstable=M6ModelCallAuthorityErrorCode.MODEL_FAILURE_UNSTABLE,
    )
    if any(
        authority.run_id != source_case.run_id
        or authority.request.case_id != source_case.case_id
        or authority.manifest_id != source_case.manifest_id
        for authority in failures
    ):
        _fail(M6ModelCallAuthorityErrorCode.MODEL_FAILURE_SCOPE_MISMATCH)
    return failures


def _validated_usages(
    source_case: Case,
    snapshot: M6M3ModelCallAuthoritySnapshot,
) -> tuple[M6M3ModelUsageAuthorityDocument, ...]:
    values: list[M6M3ModelUsageAuthorityDocument] = []
    for document in snapshot.usages:
        usage = _canonical_document(
            document.usage,
            UsageSummary,
            document.document_sha256,
            M6ModelCallAuthorityErrorCode.MODEL_USAGE_DOCUMENT_INVALID,
        )
        try:
            controlled = M6M3ModelUsageAuthorityDocument(
                usage=usage,
                request_id=document.request_id,
                response_id=document.response_id,
                case_id=document.case_id,
                case_revision=document.case_revision,
                consumer_kind=document.consumer_kind,
                consumer_id=document.consumer_id,
                accounted_at=document.accounted_at,
                document_sha256=document.document_sha256,
            )
        except (TypeError, ValueError):
            _fail(M6ModelCallAuthorityErrorCode.MODEL_USAGE_DOCUMENT_INVALID)
        if controlled != document:
            _fail(M6ModelCallAuthorityErrorCode.MODEL_USAGE_DOCUMENT_INVALID)
        if controlled.case_id != source_case.case_id:
            _fail(M6ModelCallAuthorityErrorCode.MODEL_USAGE_SCOPE_MISMATCH)
        values.append(controlled)
    usages = tuple(values)
    _require_stable_unique(
        tuple(document.request_id for document in usages),
        duplicate=M6ModelCallAuthorityErrorCode.MODEL_USAGE_DUPLICATE,
        unstable=M6ModelCallAuthorityErrorCode.MODEL_USAGE_UNSTABLE,
    )
    return usages


def _unique_by(
    values: tuple[_ModelT, ...],
    key: object,
    duplicate: M6ModelCallAuthorityErrorCode,
) -> dict[str, _ModelT]:
    if not callable(key):
        _fail(M6ModelCallAuthorityErrorCode.INVALID_ARGUMENT)
    result: dict[str, _ModelT] = {}
    for value in values:
        identity = key(value)
        if not isinstance(identity, str) or identity in result:
            _fail(duplicate)
        result[identity] = value
    return result


def _validate_repair_history(
    requests: tuple[VLMCallRequest, ...],
    responses_by_request: dict[str, VLMResponse],
    receipts_by_response: dict[str, ModelParseReceipt],
) -> None:
    requests_by_id = {request.request_id: request for request in requests}
    for request in requests:
        if isinstance(request, StructureRepairRequest):
            original = requests_by_id.get(request.original_request_id)
            original_response = responses_by_request.get(request.original_request_id)
            original_receipt = (
                receipts_by_response.get(original_response.response_id)
                if original_response is not None
                else None
            )
            if (
                not isinstance(original, VLMRequest)
                or original_response is None
                or original_receipt is None
                or original_receipt.status != ModelParseStatus.REPAIR_REQUIRED
                or original_receipt.repair_request_id != request.request_id
                or request.original_request_sha256 != original.request_sha256
                or request.original_response_id != original_response.response_id
                or request.original_response_sha256 != original_response.content_sha256
            ):
                _fail(M6ModelCallAuthorityErrorCode.REPAIR_HISTORY_INVALID)
            continue
        response = responses_by_request.get(request.request_id)
        if response is None:
            continue
        receipt = receipts_by_response.get(response.response_id)
        if receipt is None:
            continue
        if receipt.status != ModelParseStatus.REPAIR_REQUIRED:
            continue
        repair = (
            requests_by_id.get(receipt.repair_request_id)
            if receipt.repair_request_id is not None
            else None
        )
        if not isinstance(repair, StructureRepairRequest):
            _fail(M6ModelCallAuthorityErrorCode.REPAIR_HISTORY_INVALID)


def assemble_m6_locked_screening_model_calls(
    *,
    source_case: Case,
    snapshot: M6M3ModelCallAuthoritySnapshot,
) -> tuple[M6LockedModelCallInput, ...]:
    """Build one stable response-or-failure entry for every exact M3 request."""

    controlled_case, controlled_snapshot = _validated_arguments(source_case, snapshot)
    requests = _validated_requests(controlled_case, controlled_snapshot)
    responses = _validated_responses(controlled_case, controlled_snapshot)
    caches = _validated_caches(controlled_case, controlled_snapshot)
    receipts = _validated_receipts(controlled_case, controlled_snapshot)
    outputs = _validated_outputs(controlled_case, controlled_snapshot)
    failures = _validated_failures(controlled_case, controlled_snapshot)
    usages = _validated_usages(controlled_case, controlled_snapshot)

    requests_by_id = {request.request_id: request for request in requests}
    responses_by_request = _unique_by(
        responses,
        lambda response: response.request_id,
        M6ModelCallAuthorityErrorCode.MODEL_RESPONSE_DUPLICATE,
    )
    caches_by_request: dict[str, tuple[VLMCallRequest, ModelCacheEntry]] = {}
    for cache_request, entry in caches:
        if entry.request_id in caches_by_request:
            _fail(M6ModelCallAuthorityErrorCode.MODEL_CACHE_DUPLICATE)
        caches_by_request[entry.request_id] = (cache_request, entry)
    receipts_by_response = _unique_by(
        receipts,
        lambda receipt: receipt.response_id,
        M6ModelCallAuthorityErrorCode.PARSE_RECEIPT_DUPLICATE,
    )
    outputs_by_response = _unique_by(
        outputs,
        lambda output: output.response_id,
        M6ModelCallAuthorityErrorCode.PARSED_OUTPUT_DUPLICATE,
    )
    failures_by_request: dict[str, ModelCallFailureAuthority] = {}
    for authority in failures:
        request_id = authority.request.request_id
        if request_id in failures_by_request:
            _fail(M6ModelCallAuthorityErrorCode.MODEL_FAILURE_DUPLICATE)
        failures_by_request[request_id] = authority
    usages_by_request = {document.request_id: document for document in usages}

    if set(responses_by_request) - set(requests_by_id):
        _fail(M6ModelCallAuthorityErrorCode.MODEL_RESPONSE_EXTRA)
    if set(caches_by_request) - set(requests_by_id):
        _fail(M6ModelCallAuthorityErrorCode.MODEL_CACHE_EXTRA)
    if set(failures_by_request) - set(requests_by_id):
        _fail(M6ModelCallAuthorityErrorCode.MODEL_FAILURE_EXTRA)
    if set(usages_by_request) - set(requests_by_id):
        _fail(M6ModelCallAuthorityErrorCode.MODEL_USAGE_EXTRA)
    if set(receipts_by_response) - {response.response_id for response in responses}:
        _fail(M6ModelCallAuthorityErrorCode.PARSE_RECEIPT_EXTRA)
    if set(outputs_by_response) - {response.response_id for response in responses}:
        _fail(M6ModelCallAuthorityErrorCode.PARSED_OUTPUT_EXTRA)

    calls: list[M6LockedModelCallInput] = []
    for request_document, request in zip(controlled_snapshot.requests, requests, strict=True):
        response = responses_by_request.get(request.request_id)
        failure = failures_by_request.get(request.request_id)
        if response is None and failure is None:
            _fail(M6ModelCallAuthorityErrorCode.MODEL_CALL_RESULT_MISSING)
        if response is not None and failure is not None:
            _fail(M6ModelCallAuthorityErrorCode.MODEL_CALL_RESULT_CROSSED)
        request_ref = M6ReplayAuthorityRef(
            kind=M6ReplayAuthorityKind.M3_MODEL_REQUEST,
            artifact_id=request.request_id,
            document_sha256=request_document.document_sha256,
        )
        attempt_index = 0 if isinstance(request, VLMRequest) else 1
        if failure is not None:
            if request.request_id in caches_by_request or request.request_id in usages_by_request:
                _fail(M6ModelCallAuthorityErrorCode.MODEL_CALL_RESULT_CROSSED)
            if not _same_semantic_request(request, failure.request):
                _fail(M6ModelCallAuthorityErrorCode.MODEL_FAILURE_BINDING_MISMATCH)
            calls.append(
                M6LockedModelCallInput(
                    layer=M6LockedModelCallLayer.SCREENING,
                    role=M6LockedModelRole.SCREENING,
                    attempt_index=attempt_index,
                    request_ref=request_ref,
                    result_kind=M6LockedModelCallResultKind.FAILURE,
                    failure_ref=M6ReplayAuthorityRef(
                        kind=M6ReplayAuthorityKind.M3_MODEL_CALL_FAILURE,
                        artifact_id=failure.authority_id,
                        document_sha256=next(
                            document.document_sha256
                            for document in controlled_snapshot.failures
                            if document.authority.authority_id == failure.authority_id
                        ),
                    ),
                )
            )
            continue

        assert response is not None
        if not _same_request_response(request, response):
            _fail(M6ModelCallAuthorityErrorCode.MODEL_RESPONSE_BINDING_MISMATCH)
        usage_document = usages_by_request.get(request.request_id)
        if usage_document is None:
            _fail(M6ModelCallAuthorityErrorCode.MODEL_USAGE_MISSING)
        if (
            usage_document.response_id != response.response_id
            or usage_document.usage != _expected_usage(request, response)
        ):
            _fail(M6ModelCallAuthorityErrorCode.MODEL_USAGE_BINDING_MISMATCH)
        cache = caches_by_request.get(request.request_id)
        if cache is None:
            _fail(M6ModelCallAuthorityErrorCode.MODEL_CACHE_MISSING)
        cache_request, cache_entry = cache
        try:
            CachedModelResponse(entry=cache_entry, response=response)
        except ValidationError:
            _fail(M6ModelCallAuthorityErrorCode.MODEL_CACHE_BINDING_MISMATCH)
        if not _same_semantic_request(request, cache_request) or not _same_request_response(
            cache_request,
            response,
        ):
            _fail(M6ModelCallAuthorityErrorCode.MODEL_CACHE_BINDING_MISMATCH)
        receipt = receipts_by_response.get(response.response_id)
        if receipt is None:
            _fail(M6ModelCallAuthorityErrorCode.PARSE_RECEIPT_MISSING)
        if (
            receipt.request_id != request.request_id
            or receipt.request_sha256 != request.request_sha256
            or receipt.response_id != response.response_id
            or receipt.response_content_sha256 != response.content_sha256
            or receipt.attempt_index != attempt_index
            or receipt.output_schema_sha256 != request.prompt_manifest.output_schema_sha256
        ):
            _fail(M6ModelCallAuthorityErrorCode.PARSE_RECEIPT_BINDING_MISMATCH)
        output = outputs_by_response.get(response.response_id)
        if receipt.status == ModelParseStatus.PARSED:
            if output is None:
                _fail(M6ModelCallAuthorityErrorCode.PARSED_OUTPUT_MISSING)
            if (
                receipt.parsed_output_id != output.parsed_output_id
                or receipt.parsed_output_sha256 != output.parsed_output_sha256
                or output.request_id != request.request_id
                or output.response_id != response.response_id
                or output.response_content_sha256 != response.content_sha256
                or output.output_schema_sha256 != request.prompt_manifest.output_schema_sha256
            ):
                _fail(M6ModelCallAuthorityErrorCode.PARSED_OUTPUT_BINDING_MISMATCH)
        elif output is not None:
            _fail(M6ModelCallAuthorityErrorCode.PARSED_OUTPUT_EXTRA)

        cache_document = next(
            document
            for document in controlled_snapshot.caches
            if document.entry.cache_entry_id == cache_entry.cache_entry_id
        )
        receipt_document = next(
            document
            for document in controlled_snapshot.parse_receipts
            if document.receipt.parse_receipt_id == receipt.parse_receipt_id
        )
        response_document = next(
            document
            for document in controlled_snapshot.responses
            if document.response.response_id == response.response_id
        )
        output_document = (
            next(
                document
                for document in controlled_snapshot.parsed_outputs
                if document.output.parsed_output_id == output.parsed_output_id
            )
            if output is not None
            else None
        )
        calls.append(
            M6LockedModelCallInput(
                layer=M6LockedModelCallLayer.SCREENING,
                role=M6LockedModelRole.SCREENING,
                attempt_index=attempt_index,
                request_ref=request_ref,
                result_kind=M6LockedModelCallResultKind.RESPONSE,
                response_ref=M6ReplayAuthorityRef(
                    kind=M6ReplayAuthorityKind.M3_MODEL_RESPONSE,
                    artifact_id=response.response_id,
                    document_sha256=response_document.document_sha256,
                ),
                cache_ref=M6ReplayAuthorityRef(
                    kind=M6ReplayAuthorityKind.M3_MODEL_CACHE,
                    artifact_id=cache_entry.cache_entry_id,
                    document_sha256=cache_document.document_sha256,
                ),
                parse_receipt_ref=M6ReplayAuthorityRef(
                    kind=M6ReplayAuthorityKind.M3_PARSE_RECEIPT,
                    artifact_id=receipt.parse_receipt_id,
                    document_sha256=receipt_document.document_sha256,
                ),
                parsed_output_ref=(
                    M6ReplayAuthorityRef(
                        kind=M6ReplayAuthorityKind.M3_PARSED_OUTPUT,
                        artifact_id=output.parsed_output_id,
                        document_sha256=output_document.document_sha256,
                    )
                    if output is not None and output_document is not None
                    else None
                ),
                raw_content_sha256=response.content_sha256,
                raw_size_bytes=response.size_bytes,
            )
        )

    _validate_repair_history(requests, responses_by_request, receipts_by_response)
    ordered = tuple(sorted(calls, key=lambda item: item.sort_key))
    try:
        canonical = tuple(
            M6LockedModelCallInput.model_validate(
                item.model_dump(mode="json", exclude_computed_fields=True)
            )
            for item in ordered
        )
        resolve_m6_locked_model_responses(canonical)
    except (TypeError, ValueError, ValidationError):
        _fail(M6ModelCallAuthorityErrorCode.RESOLVED_MODEL_RESPONSE_INVALID)
    if canonical != ordered:
        _fail(M6ModelCallAuthorityErrorCode.LOCKED_MODEL_CALL_INVALID)
    return canonical


__all__ = [
    "M6ModelCallAuthorityError",
    "M6ModelCallAuthorityErrorCode",
    "assemble_m6_locked_screening_model_calls",
]
