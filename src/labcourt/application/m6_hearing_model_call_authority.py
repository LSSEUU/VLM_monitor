"""Assemble exact M4 hearing-call authority for locked M6 replay."""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import NoReturn, TypeVar

from pydantic import BaseModel, ValidationError

from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.cases import Case
from labcourt.contracts.enums import ModelParseStatus, VlmRole
from labcourt.contracts.hearing import (
    HearingModelCacheEntry,
    HearingModelCallFailureAuthority,
    HearingModelParseReceipt,
    HearingModelRequest,
    HearingModelResponse,
    HearingRoleOutput,
    HearingUsageReceipt,
)
from labcourt.contracts.m6_replay_locked import (
    MAX_M6_LOCKED_MODEL_CALLS_PER_CASE,
    M6LockedModelCallInput,
    M6LockedModelCallLayer,
    M6LockedModelCallResultKind,
    M6LockedModelRole,
    M6ReplayAuthorityKind,
    M6ReplayAuthorityRef,
)
from labcourt.domain.m6_semantic_projection import (
    M6ResolvedModelResponse,
    resolve_m6_locked_model_responses,
)
from labcourt.exceptions import LabCourtError
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

_ModelT = TypeVar("_ModelT", bound=BaseModel)


class M6HearingModelCallAuthorityErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    SOURCE_CASE_INVALID = "SOURCE_CASE_INVALID"
    SNAPSHOT_SCOPE_MISMATCH = "SNAPSHOT_SCOPE_MISMATCH"
    SNAPSHOT_AUTHORITY_INVALID = "SNAPSHOT_AUTHORITY_INVALID"
    SNAPSHOT_AUTHORITY_ROOT_INVALID = "SNAPSHOT_AUTHORITY_ROOT_INVALID"
    DOCUMENT_ORDER_INVALID = "DOCUMENT_ORDER_INVALID"
    MODEL_REQUEST_DUPLICATE = "MODEL_REQUEST_DUPLICATE"
    MODEL_RESPONSE_DUPLICATE = "MODEL_RESPONSE_DUPLICATE"
    MODEL_CACHE_DUPLICATE = "MODEL_CACHE_DUPLICATE"
    MODEL_USAGE_DUPLICATE = "MODEL_USAGE_DUPLICATE"
    PARSE_RECEIPT_DUPLICATE = "PARSE_RECEIPT_DUPLICATE"
    ROLE_OUTPUT_DUPLICATE = "ROLE_OUTPUT_DUPLICATE"
    MODEL_FAILURE_DUPLICATE = "MODEL_FAILURE_DUPLICATE"
    MODEL_REQUEST_DOCUMENT_INVALID = "MODEL_REQUEST_DOCUMENT_INVALID"
    MODEL_RESPONSE_DOCUMENT_INVALID = "MODEL_RESPONSE_DOCUMENT_INVALID"
    MODEL_CACHE_DOCUMENT_INVALID = "MODEL_CACHE_DOCUMENT_INVALID"
    MODEL_USAGE_DOCUMENT_INVALID = "MODEL_USAGE_DOCUMENT_INVALID"
    PARSE_RECEIPT_DOCUMENT_INVALID = "PARSE_RECEIPT_DOCUMENT_INVALID"
    ROLE_OUTPUT_DOCUMENT_INVALID = "ROLE_OUTPUT_DOCUMENT_INVALID"
    MODEL_FAILURE_DOCUMENT_INVALID = "MODEL_FAILURE_DOCUMENT_INVALID"
    MODEL_REQUEST_SCOPE_MISMATCH = "MODEL_REQUEST_SCOPE_MISMATCH"
    MODEL_RESPONSE_SCOPE_MISMATCH = "MODEL_RESPONSE_SCOPE_MISMATCH"
    MODEL_CACHE_SCOPE_MISMATCH = "MODEL_CACHE_SCOPE_MISMATCH"
    MODEL_USAGE_SCOPE_MISMATCH = "MODEL_USAGE_SCOPE_MISMATCH"
    PARSE_RECEIPT_SCOPE_MISMATCH = "PARSE_RECEIPT_SCOPE_MISMATCH"
    ROLE_OUTPUT_SCOPE_MISMATCH = "ROLE_OUTPUT_SCOPE_MISMATCH"
    MODEL_FAILURE_SCOPE_MISMATCH = "MODEL_FAILURE_SCOPE_MISMATCH"
    MODEL_REQUEST_EVIDENCE_PACK_MISSING = "MODEL_REQUEST_EVIDENCE_PACK_MISSING"
    REPAIR_HISTORY_MISSING = "REPAIR_HISTORY_MISSING"
    REPAIR_HISTORY_MISMATCH = "REPAIR_HISTORY_MISMATCH"
    MODEL_CALL_RESULT_MISSING = "MODEL_CALL_RESULT_MISSING"
    MODEL_CALL_RESULT_CROSSED = "MODEL_CALL_RESULT_CROSSED"
    MODEL_CACHE_MISSING = "MODEL_CACHE_MISSING"
    MODEL_USAGE_MISSING = "MODEL_USAGE_MISSING"
    PARSE_RECEIPT_MISSING = "PARSE_RECEIPT_MISSING"
    ROLE_OUTPUT_MISSING = "ROLE_OUTPUT_MISSING"
    MODEL_RESPONSE_BINDING_MISMATCH = "MODEL_RESPONSE_BINDING_MISMATCH"
    MODEL_CACHE_BINDING_MISMATCH = "MODEL_CACHE_BINDING_MISMATCH"
    MODEL_USAGE_BINDING_MISMATCH = "MODEL_USAGE_BINDING_MISMATCH"
    PARSE_RECEIPT_BINDING_MISMATCH = "PARSE_RECEIPT_BINDING_MISMATCH"
    ROLE_OUTPUT_BINDING_MISMATCH = "ROLE_OUTPUT_BINDING_MISMATCH"
    MODEL_FAILURE_BINDING_MISMATCH = "MODEL_FAILURE_BINDING_MISMATCH"
    MODEL_CALL_AUTHORITY_EXTRA = "MODEL_CALL_AUTHORITY_EXTRA"
    MODEL_CALL_LIMIT_EXCEEDED = "MODEL_CALL_LIMIT_EXCEEDED"
    LOCKED_CALL_INVALID = "LOCKED_CALL_INVALID"
    NORMALIZED_RESPONSE_INVALID = "NORMALIZED_RESPONSE_INVALID"


class M6HearingModelCallAuthorityError(LabCourtError):
    """The M4 snapshot cannot prove one exact locked hearing-call inventory."""

    def __init__(self, code: M6HearingModelCallAuthorityErrorCode) -> None:
        if not isinstance(code, M6HearingModelCallAuthorityErrorCode):
            raise TypeError("code must be an M6HearingModelCallAuthorityErrorCode")
        self.code = code
        super().__init__(f"M6 hearing model-call authority failed: {code.value}")


def _fail(code: M6HearingModelCallAuthorityErrorCode) -> NoReturn:
    raise M6HearingModelCallAuthorityError(code)


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _document_sha256(document: BaseModel) -> str:
    encoded = canonical_json(document.model_dump(mode="json")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _canonical_document(
    value: object,
    model_type: type[_ModelT],
    document_sha256: object,
    error_code: M6HearingModelCallAuthorityErrorCode,
) -> _ModelT:
    if not isinstance(value, model_type) or not _is_sha256(document_sha256):
        _fail(error_code)
    try:
        raw = canonical_json(value.model_dump(mode="json"))
        canonical = model_type.model_validate_json(raw)
        canonical_raw = canonical_json(canonical.model_dump(mode="json"))
    except (
        AttributeError,
        TypeError,
        ValueError,
        ValidationError,
        UnicodeError,
    ):
        _fail(error_code)
    if raw != canonical_raw or hashlib.sha256(raw.encode("utf-8")).hexdigest() != (document_sha256):
        _fail(error_code)
    return canonical


def _optional_artifact_id(value: object) -> str | None:
    artifact_id = getattr(value, "artifact_id", None)
    return artifact_id if isinstance(artifact_id, str) else None


def derive_m6_hearing_model_call_authority_root(
    *,
    source_identity_sha256: str,
    run_id: str,
    case_id: str,
    manifest_id: str,
    m4_replay_authority_root_sha256: str,
    requests: tuple[M6M4ModelRequestAuthorityDocument, ...],
    responses: tuple[M6M4ModelResponseAuthorityDocument, ...],
    caches: tuple[M6M4ModelCacheAuthorityDocument, ...],
    usages: tuple[M6M4ModelUsageAuthorityDocument, ...],
    parse_receipts: tuple[M6M4ModelParseReceiptAuthorityDocument, ...],
    role_outputs: tuple[M6M4RoleOutputAuthorityDocument, ...],
    failures: tuple[M6M4ModelCallFailureAuthorityDocument, ...],
) -> str:
    """Bind the exact case-scoped subset to its validated M4 replay root."""

    return sha256_hex(
        [
            "m6-m4-hearing-model-call-authority",
            2,
            source_identity_sha256,
            run_id,
            case_id,
            manifest_id,
            m4_replay_authority_root_sha256,
            [["REQUEST", item.request.request_id, item.document_sha256] for item in requests],
            [["RESPONSE", item.response.response_id, item.document_sha256] for item in responses],
            [["CACHE", item.entry.cache_entry_id, item.document_sha256] for item in caches],
            [["USAGE", item.receipt.usage_receipt_id, item.document_sha256] for item in usages],
            [
                ["PARSE", item.receipt.parse_receipt_id, item.document_sha256]
                for item in parse_receipts
            ],
            [["ROLE_OUTPUT", item.output.output_id, item.document_sha256] for item in role_outputs],
            [["FAILURE", item.authority.authority_id, item.document_sha256] for item in failures],
        ]
    )


def _validate_source_and_snapshot(
    source_case: object,
    snapshot: object,
) -> tuple[Case, M6M4ModelCallAuthoritySnapshot]:
    if not isinstance(source_case, Case) or not isinstance(
        snapshot, M6M4ModelCallAuthoritySnapshot
    ):
        _fail(M6HearingModelCallAuthorityErrorCode.INVALID_ARGUMENT)
    try:
        case = Case.model_validate(
            source_case.model_dump(mode="json", exclude_computed_fields=True)
        )
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6HearingModelCallAuthorityErrorCode.SOURCE_CASE_INVALID)
    if case != source_case:
        _fail(M6HearingModelCallAuthorityErrorCode.SOURCE_CASE_INVALID)
    if (
        snapshot.run_id != case.run_id
        or snapshot.case_id != case.case_id
        or snapshot.manifest_id != case.manifest_id
    ):
        _fail(M6HearingModelCallAuthorityErrorCode.SNAPSHOT_SCOPE_MISMATCH)
    if snapshot.authority_failure_count != 0:
        _fail(M6HearingModelCallAuthorityErrorCode.SNAPSHOT_AUTHORITY_INVALID)
    if (
        not _is_sha256(snapshot.source_identity_sha256)
        or not _is_sha256(snapshot.m4_replay_authority_root_sha256)
        or not _is_sha256(snapshot.model_call_authority_root_sha256)
    ):
        _fail(M6HearingModelCallAuthorityErrorCode.SNAPSHOT_AUTHORITY_ROOT_INVALID)
    return case, snapshot


def _require_stable_unique(
    identities: tuple[str, ...],
    duplicate_code: M6HearingModelCallAuthorityErrorCode,
) -> None:
    if len(identities) != len(set(identities)):
        _fail(duplicate_code)
    if identities != tuple(sorted(identities)):
        _fail(M6HearingModelCallAuthorityErrorCode.DOCUMENT_ORDER_INVALID)


def _validated_requests(
    values: object,
) -> tuple[M6M4ModelRequestAuthorityDocument, ...]:
    if not isinstance(values, tuple) or any(
        not isinstance(item, M6M4ModelRequestAuthorityDocument) for item in values
    ):
        _fail(M6HearingModelCallAuthorityErrorCode.INVALID_ARGUMENT)
    result = tuple(
        M6M4ModelRequestAuthorityDocument(
            request=_canonical_document(
                item.request,
                HearingModelRequest,
                item.document_sha256,
                M6HearingModelCallAuthorityErrorCode.MODEL_REQUEST_DOCUMENT_INVALID,
            ),
            document_sha256=item.document_sha256,
        )
        for item in values
    )
    _require_stable_unique(
        tuple(item.request.request_id for item in result),
        M6HearingModelCallAuthorityErrorCode.MODEL_REQUEST_DUPLICATE,
    )
    return result


def _validated_responses(
    values: object,
) -> tuple[M6M4ModelResponseAuthorityDocument, ...]:
    if not isinstance(values, tuple) or any(
        not isinstance(item, M6M4ModelResponseAuthorityDocument) for item in values
    ):
        _fail(M6HearingModelCallAuthorityErrorCode.INVALID_ARGUMENT)
    result = tuple(
        M6M4ModelResponseAuthorityDocument(
            response=_canonical_document(
                item.response,
                HearingModelResponse,
                item.document_sha256,
                M6HearingModelCallAuthorityErrorCode.MODEL_RESPONSE_DOCUMENT_INVALID,
            ),
            document_sha256=item.document_sha256,
        )
        for item in values
    )
    _require_stable_unique(
        tuple(item.response.response_id for item in result),
        M6HearingModelCallAuthorityErrorCode.MODEL_RESPONSE_DUPLICATE,
    )
    return result


def _validated_caches(
    values: object,
) -> tuple[M6M4ModelCacheAuthorityDocument, ...]:
    if not isinstance(values, tuple) or any(
        not isinstance(item, M6M4ModelCacheAuthorityDocument) for item in values
    ):
        _fail(M6HearingModelCallAuthorityErrorCode.INVALID_ARGUMENT)
    result = tuple(
        M6M4ModelCacheAuthorityDocument(
            entry=_canonical_document(
                item.entry,
                HearingModelCacheEntry,
                item.document_sha256,
                M6HearingModelCallAuthorityErrorCode.MODEL_CACHE_DOCUMENT_INVALID,
            ),
            document_sha256=item.document_sha256,
        )
        for item in values
    )
    _require_stable_unique(
        tuple(item.entry.cache_entry_id for item in result),
        M6HearingModelCallAuthorityErrorCode.MODEL_CACHE_DUPLICATE,
    )
    return result


def _validated_usages(
    values: object,
) -> tuple[M6M4ModelUsageAuthorityDocument, ...]:
    if not isinstance(values, tuple) or any(
        not isinstance(item, M6M4ModelUsageAuthorityDocument) for item in values
    ):
        _fail(M6HearingModelCallAuthorityErrorCode.INVALID_ARGUMENT)
    result = tuple(
        M6M4ModelUsageAuthorityDocument(
            receipt=_canonical_document(
                item.receipt,
                HearingUsageReceipt,
                item.document_sha256,
                M6HearingModelCallAuthorityErrorCode.MODEL_USAGE_DOCUMENT_INVALID,
            ),
            document_sha256=item.document_sha256,
        )
        for item in values
    )
    _require_stable_unique(
        tuple(item.receipt.usage_receipt_id for item in result),
        M6HearingModelCallAuthorityErrorCode.MODEL_USAGE_DUPLICATE,
    )
    return result


def _validated_parses(
    values: object,
) -> tuple[M6M4ModelParseReceiptAuthorityDocument, ...]:
    if not isinstance(values, tuple) or any(
        not isinstance(item, M6M4ModelParseReceiptAuthorityDocument) for item in values
    ):
        _fail(M6HearingModelCallAuthorityErrorCode.INVALID_ARGUMENT)
    result = tuple(
        M6M4ModelParseReceiptAuthorityDocument(
            receipt=_canonical_document(
                item.receipt,
                HearingModelParseReceipt,
                item.document_sha256,
                M6HearingModelCallAuthorityErrorCode.PARSE_RECEIPT_DOCUMENT_INVALID,
            ),
            document_sha256=item.document_sha256,
        )
        for item in values
    )
    _require_stable_unique(
        tuple(item.receipt.parse_receipt_id for item in result),
        M6HearingModelCallAuthorityErrorCode.PARSE_RECEIPT_DUPLICATE,
    )
    return result


def _validated_outputs(
    values: object,
) -> tuple[M6M4RoleOutputAuthorityDocument, ...]:
    if not isinstance(values, tuple) or any(
        not isinstance(item, M6M4RoleOutputAuthorityDocument) for item in values
    ):
        _fail(M6HearingModelCallAuthorityErrorCode.INVALID_ARGUMENT)
    result = tuple(
        M6M4RoleOutputAuthorityDocument(
            output=_canonical_document(
                item.output,
                HearingRoleOutput,
                item.document_sha256,
                M6HearingModelCallAuthorityErrorCode.ROLE_OUTPUT_DOCUMENT_INVALID,
            ),
            document_sha256=item.document_sha256,
        )
        for item in values
    )
    _require_stable_unique(
        tuple(item.output.output_id for item in result),
        M6HearingModelCallAuthorityErrorCode.ROLE_OUTPUT_DUPLICATE,
    )
    return result


def _validated_failures(
    values: object,
) -> tuple[M6M4ModelCallFailureAuthorityDocument, ...]:
    if not isinstance(values, tuple) or any(
        not isinstance(item, M6M4ModelCallFailureAuthorityDocument) for item in values
    ):
        _fail(M6HearingModelCallAuthorityErrorCode.INVALID_ARGUMENT)
    result = tuple(
        M6M4ModelCallFailureAuthorityDocument(
            authority=_canonical_document(
                item.authority,
                HearingModelCallFailureAuthority,
                item.document_sha256,
                M6HearingModelCallAuthorityErrorCode.MODEL_FAILURE_DOCUMENT_INVALID,
            ),
            document_sha256=item.document_sha256,
        )
        for item in values
    )
    _require_stable_unique(
        tuple(item.authority.authority_id for item in result),
        M6HearingModelCallAuthorityErrorCode.MODEL_FAILURE_DUPLICATE,
    )
    return result


def _require_source_scope(
    case: Case,
    requests: tuple[M6M4ModelRequestAuthorityDocument, ...],
    responses: tuple[M6M4ModelResponseAuthorityDocument, ...],
    caches: tuple[M6M4ModelCacheAuthorityDocument, ...],
    usages: tuple[M6M4ModelUsageAuthorityDocument, ...],
    parses: tuple[M6M4ModelParseReceiptAuthorityDocument, ...],
    outputs: tuple[M6M4RoleOutputAuthorityDocument, ...],
    failures: tuple[M6M4ModelCallFailureAuthorityDocument, ...],
) -> None:
    expected = (case.run_id, case.case_id, case.manifest_id)
    groups: tuple[
        tuple[
            tuple[tuple[str, str, str], ...],
            M6HearingModelCallAuthorityErrorCode,
        ],
        ...,
    ] = (
        (
            tuple(
                (item.request.run_id, item.request.case_id, item.request.manifest_id)
                for item in requests
            ),
            M6HearingModelCallAuthorityErrorCode.MODEL_REQUEST_SCOPE_MISMATCH,
        ),
        (
            tuple(
                (item.response.run_id, item.response.case_id, item.response.manifest_id)
                for item in responses
            ),
            M6HearingModelCallAuthorityErrorCode.MODEL_RESPONSE_SCOPE_MISMATCH,
        ),
        (
            tuple(
                (item.entry.run_id, item.entry.case_id, item.entry.manifest_id) for item in caches
            ),
            M6HearingModelCallAuthorityErrorCode.MODEL_CACHE_SCOPE_MISMATCH,
        ),
        (
            tuple(
                (item.receipt.run_id, item.receipt.case_id, item.receipt.manifest_id)
                for item in usages
            ),
            M6HearingModelCallAuthorityErrorCode.MODEL_USAGE_SCOPE_MISMATCH,
        ),
        (
            tuple(
                (item.receipt.run_id, item.receipt.case_id, item.receipt.manifest_id)
                for item in parses
            ),
            M6HearingModelCallAuthorityErrorCode.PARSE_RECEIPT_SCOPE_MISMATCH,
        ),
        (
            tuple(
                (item.output.run_id, item.output.case_id, item.output.manifest_id)
                for item in outputs
            ),
            M6HearingModelCallAuthorityErrorCode.ROLE_OUTPUT_SCOPE_MISMATCH,
        ),
        (
            tuple(
                (
                    item.authority.run_id,
                    item.authority.case_id,
                    item.authority.manifest_id,
                )
                for item in failures
            ),
            M6HearingModelCallAuthorityErrorCode.MODEL_FAILURE_SCOPE_MISMATCH,
        ),
    )
    for scopes, code in groups:
        if any(scope != expected for scope in scopes):
            _fail(code)


def _unique_relation_map(
    values: tuple[object, ...],
    key_name: str,
    duplicate_code: M6HearingModelCallAuthorityErrorCode,
) -> dict[str, object]:
    result: dict[str, object] = {}
    for item in values:
        key = getattr(item, key_name, None)
        if not isinstance(key, str):
            _fail(M6HearingModelCallAuthorityErrorCode.INVALID_ARGUMENT)
        if key in result:
            _fail(duplicate_code)
        result[key] = item
    return result


def _require_request_pack_authority(
    case: Case,
    requests: tuple[M6M4ModelRequestAuthorityDocument, ...],
) -> None:
    pack_keys = {(pack.pack_id, pack.version) for pack in case.evidence_packs}
    if any(
        (item.request.current_evidence_pack_id, item.request.current_evidence_pack_version)
        not in pack_keys
        for item in requests
    ):
        _fail(M6HearingModelCallAuthorityErrorCode.MODEL_REQUEST_EVIDENCE_PACK_MISSING)


_REPAIR_SCOPE_FIELDS = (
    "run_id",
    "case_id",
    "hearing_session_id",
    "round_index",
    "prior_acquisition_rounds",
    "prior_rework_rounds",
    "current_evidence_pack_id",
    "current_evidence_pack_version",
    "screening_ref",
    "violation_type",
    "evidence_class",
    "role",
    "provider_profile",
    "provider",
    "model",
    "revision",
    "model_manifest_id",
    "execution_location",
    "prompt_manifest",
    "hearing_prompt_bundle_sha256",
    "allowed_evidence_refs",
    "allowed_precedent_refs",
    "prosecutor_output_ref",
    "defender_output_ref",
    "precedent_retrieval_degraded",
    "precedent_retrieval_receipt_id",
    "precedent_retrieval_receipt_sha256",
    "initial_trigger_review_ref",
    "initial_defect_codes",
    "rework_review_ref",
    "rework_defect_codes",
    "backlog_retry_context",
    "manifest_id",
)


def _require_repair_history(
    repair: HearingModelRequest,
    requests_by_id: dict[str, HearingModelRequest],
    responses_by_request: dict[str, object],
    parses_by_request: dict[str, object],
) -> None:
    if repair.attempt_index == 0:
        return
    original_request_id = repair.original_request_id
    if original_request_id is None:
        _fail(M6HearingModelCallAuthorityErrorCode.REPAIR_HISTORY_MISSING)
    primary = requests_by_id.get(original_request_id)
    primary_response = responses_by_request.get(original_request_id)
    primary_parse = parses_by_request.get(original_request_id)
    if (
        primary is None
        or not isinstance(primary_response, HearingModelResponse)
        or not isinstance(primary_parse, HearingModelParseReceipt)
    ):
        _fail(M6HearingModelCallAuthorityErrorCode.REPAIR_HISTORY_MISSING)
    if (
        primary.attempt_index != 0
        or any(
            getattr(primary, field_name) != getattr(repair, field_name)
            for field_name in _REPAIR_SCOPE_FIELDS
        )
        or primary.cycle_scope_id != repair.cycle_scope_id
        or primary.cycle_scope_sha256 != repair.cycle_scope_sha256
        or not _response_matches(primary, primary_response)
        or not _parse_matches(primary, primary_response, primary_parse)
        or primary_parse.status != ModelParseStatus.REPAIR_REQUIRED
        or primary_parse.repair_request_id != repair.request_id
        or repair.original_response_id != primary_response.response_id
        or repair.original_response_content_sha256 != primary_response.content_sha256
    ):
        _fail(M6HearingModelCallAuthorityErrorCode.REPAIR_HISTORY_MISMATCH)


def _response_matches(request: HearingModelRequest, response: HearingModelResponse) -> bool:
    return (
        response.run_id == request.run_id
        and response.case_id == request.case_id
        and response.hearing_session_id == request.hearing_session_id
        and response.round_index == request.round_index
        and response.prior_acquisition_rounds == request.prior_acquisition_rounds
        and response.prior_rework_rounds == request.prior_rework_rounds
        and response.current_evidence_pack_id == request.current_evidence_pack_id
        and response.current_evidence_pack_version == request.current_evidence_pack_version
        and response.role == request.role
        and response.attempt_index == request.attempt_index
        and response.request_id == request.request_id
        and response.request_sha256 == request.request_sha256
        and response.cache_key == request.cache_key
        and response.model_manifest_id == request.model_manifest_id
        and response.manifest_id == request.manifest_id
    )


def _cache_matches(
    request: HearingModelRequest,
    response: HearingModelResponse,
    cache: HearingModelCacheEntry,
) -> bool:
    return (
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


def _usage_matches(
    request: HearingModelRequest,
    response: HearingModelResponse,
    usage: HearingUsageReceipt,
) -> bool:
    return (
        usage.run_id == request.run_id
        and usage.case_id == request.case_id
        and usage.hearing_session_id == request.hearing_session_id
        and usage.round_index == request.round_index
        and usage.role == request.role
        and usage.request_ref.artifact_id == request.request_id
        and usage.response_ref.artifact_id == response.response_id
        and usage.input_images == len(request.media)
        and usage.input_pixels == sum(item.width * item.height for item in request.media)
        and usage.input_tokens == response.input_tokens
        and usage.output_tokens == response.output_tokens
        and usage.latency_ms == response.latency_ms
        and usage.estimated_cost
        == request.budget.estimate_cost(
            input_tokens=response.input_tokens,
            output_tokens=response.output_tokens,
        )
        and usage.manifest_id == request.manifest_id
        and response.size_bytes <= request.budget.max_response_bytes
        and response.input_tokens <= request.budget.max_input_tokens
        and response.output_tokens <= request.budget.max_output_tokens
        and request.budget.allows_cost(
            input_tokens=response.input_tokens,
            output_tokens=response.output_tokens,
        )
    )


def _parse_matches(
    request: HearingModelRequest,
    response: HearingModelResponse,
    receipt: HearingModelParseReceipt,
) -> bool:
    return (
        receipt.run_id == request.run_id
        and receipt.case_id == request.case_id
        and receipt.hearing_session_id == request.hearing_session_id
        and receipt.round_index == request.round_index
        and receipt.role == request.role
        and receipt.attempt_index == request.attempt_index
        and receipt.request_id == request.request_id
        and receipt.request_sha256 == request.request_sha256
        and receipt.response_id == response.response_id
        and receipt.response_content_sha256 == response.content_sha256
        and receipt.output_schema_sha256 == request.prompt_manifest.output_schema_sha256
        and receipt.manifest_id == request.manifest_id
    )


def _output_matches(
    request: HearingModelRequest,
    response: HearingModelResponse,
    receipt: HearingModelParseReceipt,
    output: HearingRoleOutput,
) -> bool:
    return (
        receipt.status == ModelParseStatus.PARSED
        and receipt.parsed_payload_sha256 == output.payload.payload_sha256
        and output.run_id == request.run_id
        and output.case_id == request.case_id
        and output.hearing_session_id == request.hearing_session_id
        and output.round_index == request.round_index
        and output.prior_acquisition_rounds == request.prior_acquisition_rounds
        and output.prior_rework_rounds == request.prior_rework_rounds
        and output.current_evidence_pack_id == request.current_evidence_pack_id
        and output.current_evidence_pack_version == request.current_evidence_pack_version
        and output.role == request.role
        and output.prompt_manifest == request.prompt_manifest
        and output.model_manifest_id == request.model_manifest_id
        and output.request_ref.artifact_id == request.request_id
        and output.response_ref.artifact_id == response.response_id
        and output.parse_receipt_ref.artifact_id == receipt.parse_receipt_id
        and output.prosecutor_output_id == _optional_artifact_id(request.prosecutor_output_ref)
        and output.defender_output_id == _optional_artifact_id(request.defender_output_ref)
        and output.precedent_retrieval_degraded == request.precedent_retrieval_degraded
        and output.precedent_retrieval_receipt_id == request.precedent_retrieval_receipt_id
        and output.precedent_retrieval_receipt_sha256 == request.precedent_retrieval_receipt_sha256
        and output.initial_trigger_review_ref == request.initial_trigger_review_ref
        and output.initial_defect_codes == request.initial_defect_codes
        and output.rework_review_ref == request.rework_review_ref
        and output.rework_defect_codes == request.rework_defect_codes
        and output.manifest_id == request.manifest_id
    )


def _locked_role(role: VlmRole) -> M6LockedModelRole:
    mapping = {
        VlmRole.PROSECUTOR: M6LockedModelRole.PROSECUTOR,
        VlmRole.DEFENDER: M6LockedModelRole.DEFENDER,
        VlmRole.JUDGE: M6LockedModelRole.JUDGE,
    }
    try:
        return mapping[role]
    except KeyError:
        _fail(M6HearingModelCallAuthorityErrorCode.MODEL_REQUEST_SCOPE_MISMATCH)


def _authority_ref(
    kind: M6ReplayAuthorityKind,
    artifact_id: str,
    document_sha256: str,
) -> M6ReplayAuthorityRef:
    return M6ReplayAuthorityRef(
        kind=kind,
        artifact_id=artifact_id,
        document_sha256=document_sha256,
    )


def assemble_m6_locked_hearing_model_calls(
    *,
    source_case: Case,
    snapshot: M6M4ModelCallAuthoritySnapshot,
) -> tuple[M6LockedModelCallInput, ...]:
    """Build one stable, request-complete M4 call inventory without raw bytes."""

    case, authority = _validate_source_and_snapshot(source_case, snapshot)
    requests = _validated_requests(authority.requests)
    responses = _validated_responses(authority.responses)
    caches = _validated_caches(authority.caches)
    usages = _validated_usages(authority.usages)
    parses = _validated_parses(authority.parse_receipts)
    outputs = _validated_outputs(authority.role_outputs)
    failures = _validated_failures(authority.failures)
    _require_source_scope(case, requests, responses, caches, usages, parses, outputs, failures)
    _require_request_pack_authority(case, requests)

    expected_root = derive_m6_hearing_model_call_authority_root(
        source_identity_sha256=authority.source_identity_sha256,
        run_id=authority.run_id,
        case_id=authority.case_id,
        manifest_id=authority.manifest_id,
        m4_replay_authority_root_sha256=authority.m4_replay_authority_root_sha256,
        requests=requests,
        responses=responses,
        caches=caches,
        usages=usages,
        parse_receipts=parses,
        role_outputs=outputs,
        failures=failures,
    )
    if expected_root != authority.model_call_authority_root_sha256:
        _fail(M6HearingModelCallAuthorityErrorCode.SNAPSHOT_AUTHORITY_ROOT_INVALID)
    if len(requests) > MAX_M6_LOCKED_MODEL_CALLS_PER_CASE:
        _fail(M6HearingModelCallAuthorityErrorCode.MODEL_CALL_LIMIT_EXCEEDED)

    response_by_request = _unique_relation_map(
        tuple(item.response for item in responses),
        "request_id",
        M6HearingModelCallAuthorityErrorCode.MODEL_RESPONSE_DUPLICATE,
    )
    cache_by_request = _unique_relation_map(
        tuple(item.entry for item in caches),
        "request_id",
        M6HearingModelCallAuthorityErrorCode.MODEL_CACHE_DUPLICATE,
    )
    usage_by_request: dict[str, HearingUsageReceipt] = {}
    for usage_item in usages:
        request_id = usage_item.receipt.request_ref.artifact_id
        if request_id in usage_by_request:
            _fail(M6HearingModelCallAuthorityErrorCode.MODEL_USAGE_DUPLICATE)
        usage_by_request[request_id] = usage_item.receipt
    parse_by_request = _unique_relation_map(
        tuple(item.receipt for item in parses),
        "request_id",
        M6HearingModelCallAuthorityErrorCode.PARSE_RECEIPT_DUPLICATE,
    )
    output_by_parse: dict[str, HearingRoleOutput] = {}
    for item in outputs:
        parse_id = item.output.parse_receipt_ref.artifact_id
        if parse_id in output_by_parse:
            _fail(M6HearingModelCallAuthorityErrorCode.ROLE_OUTPUT_DUPLICATE)
        output_by_parse[parse_id] = item.output
    failure_by_request: dict[str, HearingModelCallFailureAuthority] = {}
    for failure_item in failures:
        request_id = failure_item.authority.request.request_id
        if request_id in failure_by_request:
            _fail(M6HearingModelCallAuthorityErrorCode.MODEL_FAILURE_DUPLICATE)
        failure_by_request[request_id] = failure_item.authority
    requests_by_id = {item.request.request_id: item.request for item in requests}
    for request in requests_by_id.values():
        _require_repair_history(
            request,
            requests_by_id,
            response_by_request,
            parse_by_request,
        )

    response_documents = {item.response.response_id: item for item in responses}
    cache_documents = {item.entry.cache_entry_id: item for item in caches}
    usage_documents = {item.receipt.usage_receipt_id: item for item in usages}
    parse_documents = {item.receipt.parse_receipt_id: item for item in parses}
    output_documents = {item.output.output_id: item for item in outputs}
    failure_documents = {item.authority.authority_id: item for item in failures}
    used_response_ids: set[str] = set()
    used_cache_ids: set[str] = set()
    used_usage_ids: set[str] = set()
    used_parse_ids: set[str] = set()
    used_output_ids: set[str] = set()
    used_failure_ids: set[str] = set()
    calls: list[M6LockedModelCallInput] = []

    for request_document in requests:
        request = request_document.request
        response_value = response_by_request.get(request.request_id)
        failure = failure_by_request.get(request.request_id)
        if response_value is None and failure is None:
            _fail(M6HearingModelCallAuthorityErrorCode.MODEL_CALL_RESULT_MISSING)
        if response_value is not None and failure is not None:
            _fail(M6HearingModelCallAuthorityErrorCode.MODEL_CALL_RESULT_CROSSED)
        request_ref = _authority_ref(
            M6ReplayAuthorityKind.M4_MODEL_REQUEST,
            request.request_id,
            request_document.document_sha256,
        )
        if failure is not None:
            if (
                request.request_id in cache_by_request
                or request.request_id in usage_by_request
                or request.request_id in parse_by_request
                or any(
                    item.output.request_ref.artifact_id == request.request_id for item in outputs
                )
            ):
                _fail(M6HearingModelCallAuthorityErrorCode.MODEL_CALL_RESULT_CROSSED)
            if failure.request != request:
                _fail(M6HearingModelCallAuthorityErrorCode.MODEL_FAILURE_BINDING_MISMATCH)
            failure_document = failure_documents[failure.authority_id]
            try:
                calls.append(
                    M6LockedModelCallInput(
                        layer=M6LockedModelCallLayer.HEARING,
                        role=_locked_role(request.role),
                        attempt_index=request.attempt_index,
                        request_ref=request_ref,
                        result_kind=M6LockedModelCallResultKind.FAILURE,
                        failure_ref=_authority_ref(
                            M6ReplayAuthorityKind.M4_MODEL_CALL_FAILURE,
                            failure.authority_id,
                            failure_document.document_sha256,
                        ),
                    )
                )
            except (TypeError, ValueError, ValidationError):
                _fail(M6HearingModelCallAuthorityErrorCode.LOCKED_CALL_INVALID)
            used_failure_ids.add(failure.authority_id)
            continue

        if not isinstance(response_value, HearingModelResponse):
            _fail(M6HearingModelCallAuthorityErrorCode.MODEL_RESPONSE_DOCUMENT_INVALID)
        response = response_value
        if not _response_matches(request, response):
            _fail(M6HearingModelCallAuthorityErrorCode.MODEL_RESPONSE_BINDING_MISMATCH)
        cache_value = cache_by_request.get(request.request_id)
        if cache_value is None:
            _fail(M6HearingModelCallAuthorityErrorCode.MODEL_CACHE_MISSING)
        if not isinstance(cache_value, HearingModelCacheEntry):
            _fail(M6HearingModelCallAuthorityErrorCode.MODEL_CACHE_DOCUMENT_INVALID)
        cache = cache_value
        if not _cache_matches(request, response, cache):
            _fail(M6HearingModelCallAuthorityErrorCode.MODEL_CACHE_BINDING_MISMATCH)
        usage_value = usage_by_request.get(request.request_id)
        if usage_value is None:
            _fail(M6HearingModelCallAuthorityErrorCode.MODEL_USAGE_MISSING)
        if not isinstance(usage_value, HearingUsageReceipt):
            _fail(M6HearingModelCallAuthorityErrorCode.MODEL_USAGE_DOCUMENT_INVALID)
        usage = usage_value
        if not _usage_matches(request, response, usage):
            _fail(M6HearingModelCallAuthorityErrorCode.MODEL_USAGE_BINDING_MISMATCH)
        parse_value = parse_by_request.get(request.request_id)
        if parse_value is None:
            _fail(M6HearingModelCallAuthorityErrorCode.PARSE_RECEIPT_MISSING)
        if not isinstance(parse_value, HearingModelParseReceipt):
            _fail(M6HearingModelCallAuthorityErrorCode.PARSE_RECEIPT_DOCUMENT_INVALID)
        parse = parse_value
        if not _parse_matches(request, response, parse):
            _fail(M6HearingModelCallAuthorityErrorCode.PARSE_RECEIPT_BINDING_MISMATCH)
        output_value = output_by_parse.get(parse.parse_receipt_id)
        if parse.status == ModelParseStatus.PARSED and output_value is None:
            _fail(M6HearingModelCallAuthorityErrorCode.ROLE_OUTPUT_MISSING)
        if parse.status != ModelParseStatus.PARSED and output_value is not None:
            _fail(M6HearingModelCallAuthorityErrorCode.MODEL_CALL_RESULT_CROSSED)
        output = output_value if isinstance(output_value, HearingRoleOutput) else None
        if output is not None and not _output_matches(request, response, parse, output):
            _fail(M6HearingModelCallAuthorityErrorCode.ROLE_OUTPUT_BINDING_MISMATCH)

        response_document = response_documents[response.response_id]
        cache_document = cache_documents[cache.cache_entry_id]
        parse_document = parse_documents[parse.parse_receipt_id]
        output_document = output_documents.get(output.output_id) if output is not None else None
        try:
            calls.append(
                M6LockedModelCallInput(
                    layer=M6LockedModelCallLayer.HEARING,
                    role=_locked_role(request.role),
                    attempt_index=request.attempt_index,
                    request_ref=request_ref,
                    result_kind=M6LockedModelCallResultKind.RESPONSE,
                    response_ref=_authority_ref(
                        M6ReplayAuthorityKind.M4_MODEL_RESPONSE,
                        response.response_id,
                        response_document.document_sha256,
                    ),
                    cache_ref=_authority_ref(
                        M6ReplayAuthorityKind.M4_MODEL_CACHE,
                        cache.cache_entry_id,
                        cache_document.document_sha256,
                    ),
                    parse_receipt_ref=_authority_ref(
                        M6ReplayAuthorityKind.M4_PARSE_RECEIPT,
                        parse.parse_receipt_id,
                        parse_document.document_sha256,
                    ),
                    parsed_output_ref=(
                        _authority_ref(
                            M6ReplayAuthorityKind.M4_ROLE_OUTPUT,
                            output.output_id,
                            output_document.document_sha256,
                        )
                        if output is not None and output_document is not None
                        else None
                    ),
                    raw_content_sha256=response.content_sha256,
                    raw_size_bytes=response.size_bytes,
                )
            )
        except (TypeError, ValueError, ValidationError):
            _fail(M6HearingModelCallAuthorityErrorCode.LOCKED_CALL_INVALID)
        used_response_ids.add(response.response_id)
        used_cache_ids.add(cache.cache_entry_id)
        used_usage_ids.add(usage.usage_receipt_id)
        used_parse_ids.add(parse.parse_receipt_id)
        if output is not None:
            used_output_ids.add(output.output_id)

    if (
        used_response_ids != set(response_documents)
        or used_cache_ids != set(cache_documents)
        or used_usage_ids != set(usage_documents)
        or used_parse_ids != set(parse_documents)
        or used_output_ids != set(output_documents)
        or used_failure_ids != set(failure_documents)
    ):
        _fail(M6HearingModelCallAuthorityErrorCode.MODEL_CALL_AUTHORITY_EXTRA)
    ordered = tuple(sorted(calls, key=lambda item: item.sort_key))
    if len(ordered) != len({item.model_call_input_id for item in ordered}):
        _fail(M6HearingModelCallAuthorityErrorCode.LOCKED_CALL_INVALID)
    return ordered


def resolve_m6_locked_hearing_model_responses(
    model_calls: tuple[M6LockedModelCallInput, ...],
) -> tuple[M6ResolvedModelResponse, ...]:
    """Normalize response content via the shared pure M6 resolver."""

    try:
        return resolve_m6_locked_model_responses(model_calls)
    except (AttributeError, TypeError, ValueError, ValidationError):
        _fail(M6HearingModelCallAuthorityErrorCode.NORMALIZED_RESPONSE_INVALID)


__all__ = [
    "M6HearingModelCallAuthorityError",
    "M6HearingModelCallAuthorityErrorCode",
    "assemble_m6_locked_hearing_model_calls",
    "derive_m6_hearing_model_call_authority_root",
    "resolve_m6_locked_hearing_model_responses",
]
