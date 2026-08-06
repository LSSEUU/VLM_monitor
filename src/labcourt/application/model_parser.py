"""Bounded, deterministic parsing for M3 screening model responses.

The parser intentionally has no filesystem, network, or clock dependencies.  It
accepts only the exact response bytes recorded by :class:`VLMResponse`, performs
resource checks before Pydantic constructs a model, and returns only controlled
diagnostics.  Provider text and raw reference values never enter an exception or
public receipt.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from pydantic import ValidationError

from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.enums import (
    ArtifactKind,
    ModelParseStatus,
    ProceduralDefectCode,
    ProceduralDefectOrigin,
    ProceduralField,
    ProceduralReasonCode,
    UnknownReferenceNamespace,
    UnknownReferenceSource,
    VlmCallPurpose,
)
from labcourt.contracts.frames import SHA256_PATTERN
from labcourt.contracts.m3_models import UnknownReferenceAttempt
from labcourt.contracts.screening import (
    ModelParseReceipt,
    ParsedScreeningOutput,
    ScreeningModelPayload,
    StructureRepairRequest,
    VLMRequest,
    VLMResponse,
)
from labcourt.contracts.storage import ArtifactRef
from labcourt.contracts.verdicts import DEFECT_ORDER, ProceduralDefect

STRICT_MODEL_PARSER_VERSION = "strict-json-v1"

_SHA256 = re.compile(SHA256_PATTERN)
_DEFECT_RANK = {code: rank for rank, code in enumerate(DEFECT_ORDER)}
_JSON_WHITESPACE = frozenset({" ", "\t", "\r", "\n"})
_SIMPLE_ESCAPES = frozenset({'"', "\\", "/", "b", "f", "n", "r", "t"})
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


class ModelParserInputErrorCode(StrEnum):
    """Stable, non-sensitive reasons an invocation cannot be trusted."""

    RAW_RESPONSE_NOT_BYTES = "RAW_RESPONSE_NOT_BYTES"
    RESPONSE_SCOPE_MISMATCH = "RESPONSE_SCOPE_MISMATCH"
    RESPONSE_SIZE_MISMATCH = "RESPONSE_SIZE_MISMATCH"
    RESPONSE_CONTENT_MISMATCH = "RESPONSE_CONTENT_MISMATCH"
    REPAIR_REQUEST_ID_REQUIRED = "REPAIR_REQUEST_ID_REQUIRED"
    REPAIR_REQUEST_ID_FORBIDDEN = "REPAIR_REQUEST_ID_FORBIDDEN"
    INVALID_REPAIR_REQUEST_ID = "INVALID_REPAIR_REQUEST_ID"


class ModelParserInputError(ValueError):
    """A controlled invocation failure that never embeds caller or provider data."""

    def __init__(self, code: ModelParserInputErrorCode) -> None:
        self.code = code
        super().__init__(code.value)


@dataclass(frozen=True, slots=True)
class ScreeningParseInspection:
    """Strict parse facts used by the caller to bind a repair request, if needed."""

    run_id: str
    case_id: str
    evidence_pack_id: str
    evidence_pack_version: int
    request_id: str
    request_sha256: str
    response_id: str
    response_content_sha256: str
    attempt_index: int
    output_schema_sha256: str
    manifest_id: str
    payload: ScreeningModelPayload | None
    defects: tuple[ProceduralDefect, ...]
    unknown_reference_attempts: tuple[UnknownReferenceAttempt, ...]

    @property
    def defect_codes(self) -> tuple[ProceduralDefectCode, ...]:
        """Return unique parser defect codes in the fixed fourteen-code order."""

        return tuple(
            code for code in DEFECT_ORDER if any(defect.code == code for defect in self.defects)
        )


@dataclass(frozen=True, slots=True)
class ModelParseResult:
    """The public parse receipt and its optional validated system envelope."""

    output: ParsedScreeningOutput | None
    receipt: ModelParseReceipt


class _JsonLimitExceeded(Exception):
    """Internal control flow; the exception has no provider-authored message."""


class _MalformedJson(Exception):
    """Internal control flow; the exception has no provider-authored message."""


def _response_ref(response_id: str) -> ArtifactRef:
    return ArtifactRef(kind=ArtifactKind.MODEL_RESPONSE, artifact_id=response_id)


def _malformed_defect(
    response_id: str,
    reason_code: ProceduralReasonCode,
) -> ProceduralDefect:
    return ProceduralDefect(
        code=ProceduralDefectCode.MALFORMED_STRUCTURE,
        origin=ProceduralDefectOrigin.PARSER,
        reason_code=reason_code,
        artifact_ref=_response_ref(response_id),
        field=ProceduralField.JSON_ROOT,
    )


def _invalid_enum_defect(
    response_id: str,
    *,
    location: tuple[str | int, ...],
    value: object,
) -> ProceduralDefect:
    return ProceduralDefect(
        code=ProceduralDefectCode.INVALID_ENUM,
        origin=ProceduralDefectOrigin.PARSER,
        reason_code=ProceduralReasonCode.UNKNOWN_ENUM_VALUE,
        artifact_ref=_response_ref(response_id),
        field=ProceduralField.ENUM_VALUE,
        value_sha256=sha256_hex(["invalid-model-enum", 1, [str(part) for part in location], value]),
    )


def _missing_field_defect(
    response_id: str,
    *,
    location: tuple[str | int, ...],
) -> ProceduralDefect:
    return ProceduralDefect(
        code=ProceduralDefectCode.MISSING_REQUIRED_FIELD,
        origin=ProceduralDefectOrigin.PARSER,
        reason_code=ProceduralReasonCode.REQUIRED_FIELD_ABSENT,
        artifact_ref=_response_ref(response_id),
        field=ProceduralField.REQUIRED_FIELD,
        value_sha256=sha256_hex(["missing-model-field", 1, [str(part) for part in location]]),
    )


def _stable_defects(defects: list[ProceduralDefect]) -> tuple[ProceduralDefect, ...]:
    by_id = {defect.defect_id: defect for defect in defects}
    return tuple(sorted(by_id.values(), key=lambda defect: defect.sort_key))


def _stable_unknown_attempts(
    attempts: list[UnknownReferenceAttempt],
) -> tuple[UnknownReferenceAttempt, ...]:
    by_key = {attempt.sort_key: attempt for attempt in attempts}
    return tuple(sorted(by_key.values(), key=lambda attempt: attempt.sort_key))


def _raise_constant(_: str) -> None:
    raise _MalformedJson


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise _MalformedJson
        output[key] = value
    return output


def _count_string_character(total: int, maximum: int) -> int:
    total += 1
    if total > maximum:
        raise _JsonLimitExceeded
    return total


def _scan_json_limits(
    text: str,
    *,
    max_depth: int,
    max_fields: int,
    max_string_chars: int,
) -> None:
    """Lexically enforce structural budgets before constructing a JSON tree."""

    depth = 0
    fields = 0
    string_chars = 0
    index = 0
    length = len(text)

    while index < length:
        char = text[index]
        if char in _JSON_WHITESPACE:
            index += 1
            continue
        if char in "{[":
            depth += 1
            if depth > max_depth:
                raise _JsonLimitExceeded
            index += 1
            continue
        if char in "}]":
            depth -= 1
            if depth < 0:
                raise _MalformedJson
            index += 1
            continue
        if char == ":":
            fields += 1
            if fields > max_fields:
                raise _JsonLimitExceeded
            index += 1
            continue
        if char != '"':
            if 0xD800 <= ord(char) <= 0xDFFF:
                raise _MalformedJson
            index += 1
            continue

        index += 1
        while index < length:
            char = text[index]
            if char == '"':
                index += 1
                break
            if char == "\\":
                index += 1
                if index >= length:
                    raise _MalformedJson
                escape = text[index]
                if escape in _SIMPLE_ESCAPES:
                    string_chars = _count_string_character(string_chars, max_string_chars)
                    index += 1
                    continue
                if escape != "u" or index + 4 >= length:
                    raise _MalformedJson
                digits = text[index + 1 : index + 5]
                if len(digits) != 4 or any(digit not in _HEX_DIGITS for digit in digits):
                    raise _MalformedJson
                codepoint = int(digits, 16)
                index += 5
                if 0xD800 <= codepoint <= 0xDBFF:
                    if index + 5 >= length or text[index : index + 2] != "\\u":
                        raise _MalformedJson
                    low_digits = text[index + 2 : index + 6]
                    if len(low_digits) != 4 or any(
                        digit not in _HEX_DIGITS for digit in low_digits
                    ):
                        raise _MalformedJson
                    low_codepoint = int(low_digits, 16)
                    if not 0xDC00 <= low_codepoint <= 0xDFFF:
                        raise _MalformedJson
                    index += 6
                elif 0xDC00 <= codepoint <= 0xDFFF:
                    raise _MalformedJson
                string_chars = _count_string_character(string_chars, max_string_chars)
                continue
            if ord(char) < 0x20 or 0xD800 <= ord(char) <= 0xDFFF:
                raise _MalformedJson
            string_chars = _count_string_character(string_chars, max_string_chars)
            index += 1
        else:
            raise _MalformedJson

    if depth != 0:
        raise _MalformedJson


def _unknown_reference_attempt(
    *,
    namespace: UnknownReferenceNamespace,
    source: UnknownReferenceSource,
    raw_value: object,
) -> UnknownReferenceAttempt:
    return UnknownReferenceAttempt(
        namespace=namespace,
        source=source,
        value_sha256=sha256_hex(
            [
                "unknown-model-reference",
                1,
                namespace.value,
                source.value,
                raw_value,
            ]
        ),
    )


def _iter_reference_values(root: dict[str, Any]) -> list[tuple[UnknownReferenceSource, Any]]:
    values: list[tuple[UnknownReferenceSource, Any]] = []
    positions = (
        (
            "frame_observations",
            "crop_id",
            UnknownReferenceSource.FRAME_OBSERVATION_CROP_ID,
        ),
        (
            "evidence_citations",
            "evidence_ref",
            UnknownReferenceSource.EVIDENCE_CITATION_REF,
        ),
        (
            "objective_claims",
            "evidence_ref",
            UnknownReferenceSource.OBJECTIVE_CLAIM_EVIDENCE_REF,
        ),
    )
    for collection_name, field_name, source in positions:
        collection = root.get(collection_name)
        if not isinstance(collection, list):
            continue
        for item in collection:
            if isinstance(item, dict) and field_name in item:
                values.append((source, item[field_name]))
    return values


def _reference_projection(
    source: UnknownReferenceSource,
    raw_value: object,
) -> tuple[str, str] | None:
    if source == UnknownReferenceSource.FRAME_OBSERVATION_CROP_ID:
        if isinstance(raw_value, str):
            return ArtifactKind.CROP.value, raw_value
        return None
    if not isinstance(raw_value, dict):
        return None
    kind = raw_value.get("kind")
    artifact_id = raw_value.get("artifact_id")
    if not isinstance(kind, str) or not isinstance(artifact_id, str):
        return None
    return kind, artifact_id


def _scan_unknown_references(
    root: dict[str, Any],
    request: VLMRequest,
) -> tuple[UnknownReferenceAttempt, ...]:
    allowed = {
        (reference.kind.value, reference.artifact_id) for reference in request.allowed_evidence_refs
    }
    attempts: list[UnknownReferenceAttempt] = []
    for source, raw_value in _iter_reference_values(root):
        if _reference_projection(source, raw_value) in allowed:
            continue
        attempts.append(
            _unknown_reference_attempt(
                namespace=UnknownReferenceNamespace.EVIDENCE,
                source=source,
                raw_value=raw_value,
            )
        )
    return _stable_unknown_attempts(attempts)


def _contains_non_finite_number(root: object) -> bool:
    """Reject JSON numbers that Python decoded to infinities before any hashing."""

    pending = [root]
    while pending:
        value = pending.pop()
        if isinstance(value, float) and not math.isfinite(value):
            return True
        if isinstance(value, dict):
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
    return False


def _classify_validation_errors(
    error: ValidationError,
    *,
    response_id: str,
) -> tuple[ProceduralDefect, ...]:
    defects: list[ProceduralDefect] = []
    malformed = False
    for item in error.errors(include_url=False, include_context=False, include_input=True):
        error_type = str(item.get("type", ""))
        location = tuple(item.get("loc", ()))
        if error_type == "missing":
            defects.append(_missing_field_defect(response_id, location=location))
        elif error_type in {"enum", "literal_error"}:
            defects.append(
                _invalid_enum_defect(
                    response_id,
                    location=location,
                    value=item.get("input"),
                )
            )
        else:
            malformed = True
    if malformed:
        defects.append(_malformed_defect(response_id, ProceduralReasonCode.MALFORMED_JSON))
    return _stable_defects(defects)


def _validate_response_scope(
    request: VLMRequest,
    response: VLMResponse,
    *,
    repair_request: StructureRepairRequest | None,
    original_response: VLMResponse | None,
) -> None:
    request_scope = (
        request.run_id,
        request.case_id,
        request.evidence_pack_id,
        request.evidence_pack_version,
        request.model_manifest_id,
        request.manifest_id,
    )
    response_scope = (
        response.run_id,
        response.case_id,
        response.evidence_pack_id,
        response.evidence_pack_version,
        response.model_manifest_id,
        response.manifest_id,
    )
    if request_scope != response_scope:
        raise ModelParserInputError(ModelParserInputErrorCode.RESPONSE_SCOPE_MISMATCH)
    if response.attempt_index == 0:
        if (
            repair_request is not None
            or original_response is not None
            or response.purpose != VlmCallPurpose.SCREENING
            or response.request_id != request.request_id
            or response.request_sha256 != request.request_sha256
            or response.cache_key != request.cache_key
        ):
            raise ModelParserInputError(ModelParserInputErrorCode.RESPONSE_SCOPE_MISMATCH)
        return

    if (
        repair_request is None
        or original_response is None
        or response.purpose != VlmCallPurpose.STRUCTURE_REPAIR
    ):
        raise ModelParserInputError(ModelParserInputErrorCode.RESPONSE_SCOPE_MISMATCH)
    _validate_response_scope(
        request,
        original_response,
        repair_request=None,
        original_response=None,
    )
    repair_binding = (
        repair_request.run_id,
        repair_request.case_id,
        repair_request.evidence_pack_id,
        repair_request.evidence_pack_version,
        repair_request.provider_profile,
        repair_request.provider,
        repair_request.model,
        repair_request.revision,
        repair_request.model_manifest_id,
        repair_request.execution_location,
        repair_request.original_request_id,
        repair_request.original_request_sha256,
        repair_request.original_response_id,
        repair_request.original_response_sha256,
        repair_request.prompt_manifest.output_schema_sha256,
        repair_request.prompt_manifest.prompt_bundle_sha256,
        repair_request.manifest_id,
    )
    expected_repair_binding = (
        request.run_id,
        request.case_id,
        request.evidence_pack_id,
        request.evidence_pack_version,
        request.provider_profile,
        request.provider,
        request.model,
        request.revision,
        request.model_manifest_id,
        request.execution_location,
        request.request_id,
        request.request_sha256,
        original_response.response_id,
        original_response.content_sha256,
        request.prompt_manifest.output_schema_sha256,
        request.prompt_manifest.prompt_bundle_sha256,
        request.manifest_id,
    )
    response_binding = (
        response.request_id,
        response.request_sha256,
        response.cache_key,
    )
    expected_response_binding = (
        repair_request.request_id,
        repair_request.request_sha256,
        repair_request.cache_key,
    )
    if repair_binding != expected_repair_binding or response_binding != expected_response_binding:
        raise ModelParserInputError(ModelParserInputErrorCode.RESPONSE_SCOPE_MISMATCH)


def _inspection(
    request: VLMRequest,
    response: VLMResponse,
    *,
    payload: ScreeningModelPayload | None,
    defects: tuple[ProceduralDefect, ...],
    unknown_reference_attempts: tuple[UnknownReferenceAttempt, ...] = (),
) -> ScreeningParseInspection:
    return ScreeningParseInspection(
        run_id=response.run_id,
        case_id=response.case_id,
        evidence_pack_id=response.evidence_pack_id,
        evidence_pack_version=response.evidence_pack_version,
        request_id=response.request_id,
        request_sha256=response.request_sha256,
        response_id=response.response_id,
        response_content_sha256=response.content_sha256,
        attempt_index=response.attempt_index,
        output_schema_sha256=request.prompt_manifest.output_schema_sha256,
        manifest_id=response.manifest_id,
        payload=payload,
        defects=defects,
        unknown_reference_attempts=unknown_reference_attempts,
    )


def inspect_screening_response(
    raw_response: bytes,
    *,
    request: VLMRequest,
    response: VLMResponse,
    repair_request: StructureRepairRequest | None = None,
    original_response: VLMResponse | None = None,
) -> ScreeningParseInspection:
    """Strictly inspect exact response bytes without deciding a repair identity.

    An invalid model response is represented as parser defects.  Only corrupted
    application bindings raise :class:`ModelParserInputError`.
    """

    if not isinstance(raw_response, bytes):
        raise ModelParserInputError(ModelParserInputErrorCode.RAW_RESPONSE_NOT_BYTES)
    _validate_response_scope(
        request,
        response,
        repair_request=repair_request,
        original_response=original_response,
    )
    if len(raw_response) != response.size_bytes:
        raise ModelParserInputError(ModelParserInputErrorCode.RESPONSE_SIZE_MISMATCH)

    if len(raw_response) > request.budget.max_response_bytes:
        return _inspection(
            request,
            response,
            payload=None,
            defects=(
                _malformed_defect(
                    response.response_id,
                    ProceduralReasonCode.RESPONSE_LIMIT_EXCEEDED,
                ),
            ),
        )
    if hashlib.sha256(raw_response).hexdigest() != response.content_sha256:
        raise ModelParserInputError(ModelParserInputErrorCode.RESPONSE_CONTENT_MISMATCH)

    try:
        text = raw_response.decode("utf-8", errors="strict")
        _scan_json_limits(
            text,
            max_depth=request.budget.max_json_depth,
            max_fields=request.budget.max_json_fields,
            max_string_chars=request.budget.max_string_chars,
        )
    except _JsonLimitExceeded:
        return _inspection(
            request,
            response,
            payload=None,
            defects=(
                _malformed_defect(
                    response.response_id,
                    ProceduralReasonCode.RESPONSE_LIMIT_EXCEEDED,
                ),
            ),
        )
    except (UnicodeDecodeError, _MalformedJson):
        return _inspection(
            request,
            response,
            payload=None,
            defects=(
                _malformed_defect(
                    response.response_id,
                    ProceduralReasonCode.MALFORMED_JSON,
                ),
            ),
        )

    try:
        root = json.loads(
            text,
            parse_constant=_raise_constant,
            object_pairs_hook=_unique_object,
        )
    except (ValueError, _MalformedJson, OverflowError, RecursionError):
        return _inspection(
            request,
            response,
            payload=None,
            defects=(
                _malformed_defect(
                    response.response_id,
                    ProceduralReasonCode.MALFORMED_JSON,
                ),
            ),
        )
    if not isinstance(root, dict):
        return _inspection(
            request,
            response,
            payload=None,
            defects=(
                _malformed_defect(
                    response.response_id,
                    ProceduralReasonCode.ROOT_NOT_OBJECT,
                ),
            ),
        )
    if _contains_non_finite_number(root):
        return _inspection(
            request,
            response,
            payload=None,
            defects=(
                _malformed_defect(
                    response.response_id,
                    ProceduralReasonCode.MALFORMED_JSON,
                ),
            ),
        )

    unknown_attempts = _scan_unknown_references(root, request)
    try:
        payload = ScreeningModelPayload.model_validate_json(raw_response, strict=True)
    except ValidationError as error:
        return _inspection(
            request,
            response,
            payload=None,
            defects=_classify_validation_errors(error, response_id=response.response_id),
            unknown_reference_attempts=unknown_attempts,
        )
    return _inspection(
        request,
        response,
        payload=payload,
        defects=(),
        unknown_reference_attempts=unknown_attempts,
    )


def finalize_screening_parse(
    inspection: ScreeningParseInspection,
    *,
    parser_version: str = STRICT_MODEL_PARSER_VERSION,
    repair_request_id: str | None = None,
) -> ModelParseResult:
    """Build the public envelope and receipt after the caller binds any repair."""

    output: ParsedScreeningOutput | None = None
    if inspection.payload is not None:
        if repair_request_id is not None:
            raise ModelParserInputError(ModelParserInputErrorCode.REPAIR_REQUEST_ID_FORBIDDEN)
        output = ParsedScreeningOutput(
            run_id=inspection.run_id,
            case_id=inspection.case_id,
            evidence_pack_id=inspection.evidence_pack_id,
            evidence_pack_version=inspection.evidence_pack_version,
            request_id=inspection.request_id,
            response_id=inspection.response_id,
            response_content_sha256=inspection.response_content_sha256,
            output_schema_sha256=inspection.output_schema_sha256,
            payload=inspection.payload,
            manifest_id=inspection.manifest_id,
        )
        status = ModelParseStatus.PARSED
    elif inspection.attempt_index == 0:
        if repair_request_id is None:
            raise ModelParserInputError(ModelParserInputErrorCode.REPAIR_REQUEST_ID_REQUIRED)
        if _SHA256.fullmatch(repair_request_id) is None:
            raise ModelParserInputError(ModelParserInputErrorCode.INVALID_REPAIR_REQUEST_ID)
        status = ModelParseStatus.REPAIR_REQUIRED
    else:
        if repair_request_id is not None:
            raise ModelParserInputError(ModelParserInputErrorCode.REPAIR_REQUEST_ID_FORBIDDEN)
        status = ModelParseStatus.INVALID_FINAL

    receipt = ModelParseReceipt(
        run_id=inspection.run_id,
        case_id=inspection.case_id,
        evidence_pack_id=inspection.evidence_pack_id,
        evidence_pack_version=inspection.evidence_pack_version,
        request_id=inspection.request_id,
        request_sha256=inspection.request_sha256,
        response_id=inspection.response_id,
        response_content_sha256=inspection.response_content_sha256,
        attempt_index=inspection.attempt_index,
        parser_version=parser_version,
        output_schema_sha256=inspection.output_schema_sha256,
        status=status,
        defects=inspection.defects,
        unknown_reference_attempts=inspection.unknown_reference_attempts,
        parsed_output_id=output.parsed_output_id if output is not None else None,
        parsed_output_sha256=(output.parsed_output_sha256 if output is not None else None),
        repair_request_id=(
            repair_request_id if status == ModelParseStatus.REPAIR_REQUIRED else None
        ),
        manifest_id=inspection.manifest_id,
    )
    return ModelParseResult(output=output, receipt=receipt)


def parse_screening_response(
    raw_response: bytes,
    *,
    request: VLMRequest,
    response: VLMResponse,
    repair_request: StructureRepairRequest | None = None,
    original_response: VLMResponse | None = None,
    parser_version: str = STRICT_MODEL_PARSER_VERSION,
    repair_request_id: str | None = None,
) -> ModelParseResult:
    """Convenience wrapper for callers that already know the repair request ID."""

    inspection = inspect_screening_response(
        raw_response,
        request=request,
        response=response,
        repair_request=repair_request,
        original_response=original_response,
    )
    return finalize_screening_parse(
        inspection,
        parser_version=parser_version,
        repair_request_id=repair_request_id,
    )


__all__ = [
    "STRICT_MODEL_PARSER_VERSION",
    "ModelParseResult",
    "ModelParserInputError",
    "ModelParserInputErrorCode",
    "ScreeningParseInspection",
    "finalize_screening_parse",
    "inspect_screening_response",
    "parse_screening_response",
]
