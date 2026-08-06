"""Strict M4 journal codec and request/response binding helpers.

This module is deliberately independent from the frozen M3 journal codec.  It
shares only the canonical JSON primitive and the secure filesystem boundary.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Final

from pydantic import ValidationError

from labcourt.adapters.storage.secure_workspace import SecureFileSnapshot
from labcourt.contracts.canonical import canonical_bytes
from labcourt.contracts.hearing import (
    HearingModelRequest,
    HearingModelResponse,
    derive_hearing_model_response_id,
)
from labcourt.exceptions import ArtifactIntegrityViolation
from labcourt.ports.hearing_vlm import (
    HearingModelResponseStoreError,
    HearingModelResponseStoreFailureCode,
)

HEARING_JOURNAL_SCHEMA: Final = "m4-hearing-model-response-publication-journal-v1"
HEARING_JOURNAL_HASH_DOMAIN: Final = "labcourt:hearing-model-response-publication-journal"
MAX_HEARING_JOURNAL_BYTES: Final = 64 * 1024

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_JOURNAL_KEYS = frozenset({"schema_version", "request_binding", "response", "journal_sha256"})
_REQUEST_BINDING_KEYS = frozenset(
    {
        "request_schema_version",
        "purpose",
        "run_id",
        "case_id",
        "hearing_session_id",
        "cycle_scope_id",
        "cycle_scope_sha256",
        "round_index",
        "prior_acquisition_rounds",
        "prior_rework_rounds",
        "current_evidence_pack_id",
        "current_evidence_pack_version",
        "role",
        "attempt_index",
        "original_request_id",
        "original_response_id",
        "original_response_content_sha256",
        "repair_context_sha256",
        "backlog_retry_context_id",
        "request_id",
        "request_sha256",
        "cache_key",
        "provider_profile",
        "provider",
        "model",
        "revision",
        "model_manifest_id",
        "execution_location",
        "prompt_manifest_id",
        "hearing_prompt_bundle_sha256",
        "rendered_prompt_sha256",
        "hearing_context_sha256",
        "output_schema_sha256",
        "manifest_id",
    }
)


class _DuplicateJournalField(ValueError):
    pass


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJournalField
        result[key] = value
    return result


def _reject_nonfinite(_value: str) -> object:
    raise ValueError


def require_hearing_request(request: object) -> HearingModelRequest:
    """Reject lookalikes and revalidate every computed request identity."""

    if type(request) is not HearingModelRequest:
        raise HearingModelResponseStoreError(HearingModelResponseStoreFailureCode.INVALID_ARGUMENT)
    try:
        validated = HearingModelRequest.model_validate(request.model_dump(mode="json"))
    except (TypeError, ValueError, ValidationError):
        raise HearingModelResponseStoreError(
            HearingModelResponseStoreFailureCode.INVALID_ARGUMENT
        ) from None
    if validated != request:
        raise HearingModelResponseStoreError(HearingModelResponseStoreFailureCode.INVALID_ARGUMENT)
    return validated


def require_hearing_response(response: object) -> HearingModelResponse:
    """Reject lookalikes and revalidate the response's content-derived ID."""

    if type(response) is not HearingModelResponse:
        raise HearingModelResponseStoreError(HearingModelResponseStoreFailureCode.INVALID_ARGUMENT)
    try:
        validated = HearingModelResponse.model_validate(response.model_dump(mode="json"))
    except (TypeError, ValueError, ValidationError):
        raise HearingModelResponseStoreError(
            HearingModelResponseStoreFailureCode.INVALID_ARGUMENT
        ) from None
    if validated != response:
        raise HearingModelResponseStoreError(HearingModelResponseStoreFailureCode.INVALID_ARGUMENT)
    return validated


def hearing_request_binding(request: HearingModelRequest) -> dict[str, object]:
    """Return the explicit M4 recovery authority carried by one journal."""

    retry_context = request.backlog_retry_context
    return {
        "request_schema_version": request.schema_version,
        "purpose": request.purpose,
        "run_id": request.run_id,
        "case_id": request.case_id,
        "hearing_session_id": request.hearing_session_id,
        "cycle_scope_id": request.cycle_scope_id,
        "cycle_scope_sha256": request.cycle_scope_sha256,
        "round_index": request.round_index,
        "prior_acquisition_rounds": request.prior_acquisition_rounds,
        "prior_rework_rounds": request.prior_rework_rounds,
        "current_evidence_pack_id": request.current_evidence_pack_id,
        "current_evidence_pack_version": request.current_evidence_pack_version,
        "role": request.role.value,
        "attempt_index": request.attempt_index,
        "original_request_id": request.original_request_id,
        "original_response_id": request.original_response_id,
        "original_response_content_sha256": request.original_response_content_sha256,
        "repair_context_sha256": request.repair_context_sha256,
        "backlog_retry_context_id": (
            retry_context.context_id if retry_context is not None else None
        ),
        "request_id": request.request_id,
        "request_sha256": request.request_sha256,
        "cache_key": request.cache_key,
        "provider_profile": request.provider_profile,
        "provider": request.provider,
        "model": request.model,
        "revision": request.revision,
        "model_manifest_id": request.model_manifest_id,
        "execution_location": request.execution_location.value,
        "prompt_manifest_id": request.prompt_manifest.prompt_manifest_id,
        "hearing_prompt_bundle_sha256": request.hearing_prompt_bundle_sha256,
        "rendered_prompt_sha256": request.rendered_prompt_sha256,
        "hearing_context_sha256": request.hearing_context_sha256,
        "output_schema_sha256": request.prompt_manifest.output_schema_sha256,
        "manifest_id": request.manifest_id,
    }


def hearing_response_matches_request(
    request: HearingModelRequest,
    response: HearingModelResponse,
) -> bool:
    """Check every M4 response field that is delegated from its exact request."""

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


def hearing_response_within_request_budget(
    request: HearingModelRequest,
    response: HearingModelResponse,
) -> bool:
    return (
        response.size_bytes <= request.budget.max_response_bytes
        and response.input_tokens <= request.budget.max_input_tokens
        and response.output_tokens <= request.budget.max_output_tokens
        and request.budget.allows_cost(
            input_tokens=response.input_tokens,
            output_tokens=response.output_tokens,
        )
    )


def build_hearing_response(
    request: HearingModelRequest,
    *,
    final_relative: str,
    content_sha256: str,
    size_bytes: int,
    input_tokens: int,
    output_tokens: int,
    latency_ms: int,
) -> HearingModelResponse:
    try:
        return HearingModelResponse(
            run_id=request.run_id,
            case_id=request.case_id,
            hearing_session_id=request.hearing_session_id,
            round_index=request.round_index,
            prior_acquisition_rounds=request.prior_acquisition_rounds,
            prior_rework_rounds=request.prior_rework_rounds,
            current_evidence_pack_id=request.current_evidence_pack_id,
            current_evidence_pack_version=request.current_evidence_pack_version,
            role=request.role,
            attempt_index=request.attempt_index,
            request_id=request.request_id,
            request_sha256=request.request_sha256,
            cache_key=request.cache_key,
            raw_response_ref=final_relative,
            content_sha256=content_sha256,
            size_bytes=size_bytes,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            latency_ms=latency_ms,
            model_manifest_id=request.model_manifest_id,
            manifest_id=request.manifest_id,
        )
    except (TypeError, ValueError, ValidationError):
        raise HearingModelResponseStoreError(
            HearingModelResponseStoreFailureCode.RESPONSE_RECEIPT_INVALID
        ) from None


def _journal_body(
    request: HearingModelRequest,
    response: HearingModelResponse,
) -> dict[str, object]:
    return {
        "schema_version": HEARING_JOURNAL_SCHEMA,
        "request_binding": hearing_request_binding(request),
        "response": response.model_dump(mode="json"),
    }


def encode_hearing_response_journal(
    request: HearingModelRequest,
    response: HearingModelResponse,
) -> bytes:
    body = _journal_body(request, response)
    journal_sha256 = hashlib.sha256(
        canonical_bytes([HEARING_JOURNAL_HASH_DOMAIN, 1, body])
    ).hexdigest()
    return canonical_bytes({**body, "journal_sha256": journal_sha256})


def decode_hearing_response_journal(
    request: HearingModelRequest,
    snapshot: SecureFileSnapshot,
    *,
    expected_relative_path: str,
) -> HearingModelResponse:
    """Decode one canonical, self-hashed, exact-request M4 journal."""

    try:
        if snapshot.relative_path != expected_relative_path:
            raise ValueError
        root = json.loads(
            snapshot.bytes.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_nonfinite,
        )
        if not isinstance(root, dict) or frozenset(root) != _JOURNAL_KEYS:
            raise ValueError
        if canonical_bytes(root) != snapshot.bytes:
            raise ValueError
        if root["schema_version"] != HEARING_JOURNAL_SCHEMA:
            raise ValueError
        binding = root["request_binding"]
        response_document = root["response"]
        journal_sha256 = root["journal_sha256"]
        if (
            not isinstance(binding, dict)
            or frozenset(binding) != _REQUEST_BINDING_KEYS
            or binding != hearing_request_binding(request)
            or not isinstance(response_document, dict)
            or not isinstance(journal_sha256, str)
            or _SHA256.fullmatch(journal_sha256) is None
        ):
            raise ValueError
        body = {
            "schema_version": root["schema_version"],
            "request_binding": binding,
            "response": response_document,
        }
        expected_journal_sha256 = hashlib.sha256(
            canonical_bytes([HEARING_JOURNAL_HASH_DOMAIN, 1, body])
        ).hexdigest()
        if journal_sha256 != expected_journal_sha256:
            raise ValueError
        response = HearingModelResponse.model_validate(response_document)
        if not hearing_response_matches_request(request, response):
            raise ValueError
        if not hearing_response_within_request_budget(request, response):
            raise ValueError
        if encode_hearing_response_journal(request, response) != snapshot.bytes:
            raise ValueError
        return response
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValidationError,
        TypeError,
        ValueError,
        OverflowError,
        RecursionError,
    ):
        raise ArtifactIntegrityViolation("HEARING_MODEL_RESPONSE_JOURNAL_INVALID") from None


def expected_hearing_response_id(
    request: HearingModelRequest,
    content_sha256: str,
) -> str:
    return derive_hearing_model_response_id(
        request.run_id,
        request.request_id,
        content_sha256,
    )
