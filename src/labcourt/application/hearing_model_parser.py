"""Bounded, role-specific parsing for M4 hearing model responses."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from pydantic import ValidationError

from labcourt.application._bounded_json import (
    BoundedJsonError,
    BoundedJsonFailureCode,
    load_bounded_json_object,
)
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.enums import (
    ArtifactKind,
    ModelParseStatus,
    ProceduralDefectCode,
    ProceduralDefectOrigin,
    ProceduralField,
    ProceduralReasonCode,
    UnknownReferenceNamespace,
    VlmRole,
)
from labcourt.contracts.frames import SHA256_PATTERN
from labcourt.contracts.hearing import (
    DefenderModelPayload,
    HearingModelParseReceipt,
    HearingModelPayload,
    HearingModelRequest,
    HearingModelResponse,
    HearingUnknownReferenceAttempt,
    HearingUnknownReferenceSource,
    JudgeModelPayload,
    ProsecutorModelPayload,
)
from labcourt.contracts.storage import ArtifactRef
from labcourt.contracts.verdicts import DEFECT_ORDER, ProceduralDefect

STRICT_HEARING_MODEL_PARSER_VERSION = "strict-hearing-json-v1"

_SHA256 = re.compile(SHA256_PATTERN)
_DEFECT_RANK = {code: rank for rank, code in enumerate(DEFECT_ORDER)}


class HearingModelParserInputErrorCode(StrEnum):
    RAW_RESPONSE_NOT_BYTES = "RAW_RESPONSE_NOT_BYTES"
    RESPONSE_SCOPE_MISMATCH = "RESPONSE_SCOPE_MISMATCH"
    RESPONSE_SIZE_MISMATCH = "RESPONSE_SIZE_MISMATCH"
    RESPONSE_CONTENT_MISMATCH = "RESPONSE_CONTENT_MISMATCH"
    REPAIR_REQUEST_ID_REQUIRED = "REPAIR_REQUEST_ID_REQUIRED"
    REPAIR_REQUEST_ID_FORBIDDEN = "REPAIR_REQUEST_ID_FORBIDDEN"
    INVALID_REPAIR_REQUEST_ID = "INVALID_REPAIR_REQUEST_ID"


class HearingModelParserInputError(ValueError):
    """Controlled application-authority failure without provider text."""

    def __init__(self, reason_code: HearingModelParserInputErrorCode) -> None:
        if not isinstance(reason_code, HearingModelParserInputErrorCode):
            raise TypeError("reason_code must be a HearingModelParserInputErrorCode")
        self.reason_code = reason_code
        super().__init__(f"hearing model parser input failed: {reason_code.value}")


@dataclass(frozen=True, slots=True)
class HearingParseInspection:
    """Strict inspection before a repair request identity is available."""

    request: HearingModelRequest
    response: HearingModelResponse
    payload: HearingModelPayload | None
    defects: tuple[ProceduralDefect, ...]
    unknown_reference_attempts: tuple[HearingUnknownReferenceAttempt, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.request, HearingModelRequest):
            raise TypeError("inspection request must be a HearingModelRequest")
        if not isinstance(self.response, HearingModelResponse):
            raise TypeError("inspection response must be a HearingModelResponse")
        if self.payload is not None and not isinstance(
            self.payload,
            ProsecutorModelPayload | DefenderModelPayload | JudgeModelPayload,
        ):
            raise TypeError("inspection payload must be an M4 role payload")
        if any(not isinstance(item, ProceduralDefect) for item in self.defects):
            raise TypeError("inspection defects must be ProceduralDefect values")
        if any(
            not isinstance(item, HearingUnknownReferenceAttempt)
            for item in self.unknown_reference_attempts
        ):
            raise TypeError(
                "inspection unknown references must be HearingUnknownReferenceAttempt values"
            )
        if (self.payload is None) == (not self.defects):
            raise ValueError("inspection must contain exactly one of payload or defects")
        if self.payload is not None and self.payload.role != self.request.role:
            raise ValueError("inspection payload role conflicts with its request")
        _validate_response_scope(self.request, self.response)


@dataclass(frozen=True, slots=True)
class HearingModelParseResult:
    payload: HearingModelPayload | None
    receipt: HearingModelParseReceipt

    def __post_init__(self) -> None:
        if self.payload is not None and self.receipt.parsed_payload_sha256 != (
            self.payload.payload_sha256
        ):
            raise ValueError("hearing parse result payload conflicts with its receipt")
        if (self.payload is None) != (self.receipt.status != ModelParseStatus.PARSED):
            raise ValueError("hearing parse result status conflicts with its payload")


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
    entries: list[tuple[tuple[str | int, ...], object]],
) -> ProceduralDefect:
    projection = sorted(
        (
            [str(part) for part in location],
            sha256_hex(["invalid-hearing-enum-value", 1, value]),
        )
        for location, value in entries
    )
    return ProceduralDefect(
        code=ProceduralDefectCode.INVALID_ENUM,
        origin=ProceduralDefectOrigin.PARSER,
        reason_code=ProceduralReasonCode.UNKNOWN_ENUM_VALUE,
        artifact_ref=_response_ref(response_id),
        field=ProceduralField.ENUM_VALUE,
        value_sha256=sha256_hex(["invalid-hearing-enum-set", 1, projection]),
    )


def _missing_field_defect(
    response_id: str,
    locations: list[tuple[str | int, ...]],
) -> ProceduralDefect:
    projection = sorted([str(part) for part in location] for location in locations)
    return ProceduralDefect(
        code=ProceduralDefectCode.MISSING_REQUIRED_FIELD,
        origin=ProceduralDefectOrigin.PARSER,
        reason_code=ProceduralReasonCode.REQUIRED_FIELD_ABSENT,
        artifact_ref=_response_ref(response_id),
        field=ProceduralField.REQUIRED_FIELD,
        value_sha256=sha256_hex(["missing-hearing-field-set", 1, projection]),
    )


def _classify_validation_errors(
    error: ValidationError,
    *,
    response_id: str,
) -> tuple[ProceduralDefect, ...]:
    missing: list[tuple[str | int, ...]] = []
    invalid_enums: list[tuple[tuple[str | int, ...], object]] = []
    malformed = False
    for item in error.errors(include_url=False, include_context=False, include_input=True):
        error_type = str(item.get("type", ""))
        location = tuple(item.get("loc", ()))
        if error_type == "missing":
            missing.append(location)
        elif error_type in {"enum", "literal_error"}:
            invalid_enums.append((location, item.get("input")))
        else:
            malformed = True
    defects: list[ProceduralDefect] = []
    if malformed:
        defects.append(_malformed_defect(response_id, ProceduralReasonCode.MALFORMED_JSON))
    if invalid_enums:
        defects.append(_invalid_enum_defect(response_id, invalid_enums))
    if missing:
        defects.append(_missing_field_defect(response_id, missing))
    return tuple(sorted(defects, key=lambda defect: _DEFECT_RANK[defect.code]))


def _validate_response_scope(
    request: HearingModelRequest,
    response: HearingModelResponse,
) -> None:
    if not isinstance(request, HearingModelRequest) or not isinstance(
        response, HearingModelResponse
    ):
        raise HearingModelParserInputError(HearingModelParserInputErrorCode.RESPONSE_SCOPE_MISMATCH)
    request_scope = (
        request.run_id,
        request.case_id,
        request.hearing_session_id,
        request.round_index,
        request.prior_acquisition_rounds,
        request.prior_rework_rounds,
        request.current_evidence_pack_id,
        request.current_evidence_pack_version,
        request.role,
        request.attempt_index,
        request.request_id,
        request.request_sha256,
        request.cache_key,
        request.model_manifest_id,
        request.manifest_id,
    )
    response_scope = (
        response.run_id,
        response.case_id,
        response.hearing_session_id,
        response.round_index,
        response.prior_acquisition_rounds,
        response.prior_rework_rounds,
        response.current_evidence_pack_id,
        response.current_evidence_pack_version,
        response.role,
        response.attempt_index,
        response.request_id,
        response.request_sha256,
        response.cache_key,
        response.model_manifest_id,
        response.manifest_id,
    )
    if request_scope != response_scope:
        raise HearingModelParserInputError(HearingModelParserInputErrorCode.RESPONSE_SCOPE_MISMATCH)


def _reference_projection(
    raw_value: object,
    *,
    crop_id: bool = False,
) -> tuple[str, str] | None:
    if crop_id:
        return (ArtifactKind.CROP.value, raw_value) if isinstance(raw_value, str) else None
    if not isinstance(raw_value, dict):
        return None
    kind = raw_value.get("kind")
    artifact_id = raw_value.get("artifact_id")
    if not isinstance(kind, str) or not isinstance(artifact_id, str):
        return None
    return kind, artifact_id


def _collection_values(
    container: object,
    collection_name: str,
    field_name: str,
) -> list[object]:
    if not isinstance(container, dict):
        return []
    collection = container.get(collection_name)
    if not isinstance(collection, list):
        return []
    return [
        item[field_name] for item in collection if isinstance(item, dict) and field_name in item
    ]


def _reference_values(
    root: dict[str, Any],
) -> list[
    tuple[
        UnknownReferenceNamespace,
        HearingUnknownReferenceSource,
        object,
        bool,
    ]
]:
    values: list[
        tuple[
            UnknownReferenceNamespace,
            HearingUnknownReferenceSource,
            object,
            bool,
        ]
    ] = []

    for raw_argument in _collection_values(root, "arguments", "evidence_refs"):
        if isinstance(raw_argument, list):
            values.extend(
                (
                    UnknownReferenceNamespace.EVIDENCE,
                    HearingUnknownReferenceSource.ARGUMENT_EVIDENCE_REF,
                    raw_ref,
                    False,
                )
                for raw_ref in raw_argument
            )

    for raw_response in _collection_values(root, "judge_responses", "evidence_refs"):
        if isinstance(raw_response, list):
            values.extend(
                (
                    UnknownReferenceNamespace.EVIDENCE,
                    HearingUnknownReferenceSource.JUDGE_RESPONSE_EVIDENCE_REF,
                    raw_ref,
                    False,
                )
                for raw_ref in raw_response
            )

    applications = root.get("precedent_applications")
    if isinstance(applications, list):
        for application in applications:
            if not isinstance(application, dict):
                continue
            if "precedent_ref" in application:
                values.append(
                    (
                        UnknownReferenceNamespace.PRECEDENT,
                        HearingUnknownReferenceSource.PRECEDENT_APPLICATION_ID,
                        application["precedent_ref"],
                        False,
                    )
                )
            difference_refs = application.get("fact_difference_refs")
            if isinstance(difference_refs, list):
                values.extend(
                    (
                        UnknownReferenceNamespace.EVIDENCE,
                        HearingUnknownReferenceSource.PRECEDENT_FACT_DIFFERENCE_REF,
                        raw_ref,
                        False,
                    )
                    for raw_ref in difference_refs
                )

    outcome = root.get("outcome")
    if not isinstance(outcome, dict):
        return values
    for raw_citation in _collection_values(outcome, "evidence_citations", "evidence_ref"):
        values.append(
            (
                UnknownReferenceNamespace.EVIDENCE,
                HearingUnknownReferenceSource.JUDGE_CITATION_REF,
                raw_citation,
                False,
            )
        )
    for raw_claim in _collection_values(outcome, "objective_claims", "evidence_ref"):
        values.append(
            (
                UnknownReferenceNamespace.EVIDENCE,
                HearingUnknownReferenceSource.OBJECTIVE_CLAIM_EVIDENCE_REF,
                raw_claim,
                False,
            )
        )
    sufficiency = outcome.get("observation_sufficiency")
    for raw_crop_id in _collection_values(sufficiency, "observations", "crop_id"):
        values.append(
            (
                UnknownReferenceNamespace.EVIDENCE,
                HearingUnknownReferenceSource.OBSERVATION_CROP_ID,
                raw_crop_id,
                True,
            )
        )
    acquisition = outcome.get("request")
    if isinstance(acquisition, dict):
        supporting = acquisition.get("supporting_evidence_refs")
        if isinstance(supporting, list):
            values.extend(
                (
                    UnknownReferenceNamespace.EVIDENCE,
                    HearingUnknownReferenceSource.ACQUISITION_SUPPORTING_EVIDENCE_REF,
                    raw_ref,
                    False,
                )
                for raw_ref in supporting
            )
    return values


def _unknown_reference_attempt(
    namespace: UnknownReferenceNamespace,
    source: HearingUnknownReferenceSource,
    raw_value: object,
) -> HearingUnknownReferenceAttempt:
    return HearingUnknownReferenceAttempt(
        namespace=namespace,
        source=source,
        value_sha256=sha256_hex(
            [
                "unknown-hearing-model-reference",
                1,
                namespace.value,
                source.value,
                raw_value,
            ]
        ),
    )


def _scan_unknown_references(
    root: dict[str, Any],
    request: HearingModelRequest,
) -> tuple[HearingUnknownReferenceAttempt, ...]:
    allowed_evidence = {
        (reference.kind.value, reference.artifact_id) for reference in request.allowed_evidence_refs
    }
    allowed_precedents = {
        (reference.kind.value, reference.artifact_id)
        for reference in request.allowed_precedent_refs
    }
    attempts: dict[
        tuple[str, str, str],
        HearingUnknownReferenceAttempt,
    ] = {}
    for namespace, source, raw_value, is_crop_id in _reference_values(root):
        projection = _reference_projection(raw_value, crop_id=is_crop_id)
        allowed = (
            allowed_precedents
            if namespace == UnknownReferenceNamespace.PRECEDENT
            else allowed_evidence
        )
        if projection in allowed:
            continue
        attempt = _unknown_reference_attempt(namespace, source, raw_value)
        attempts[attempt.sort_key] = attempt
    return tuple(attempts[key] for key in sorted(attempts))


def _payload_model(
    role: VlmRole,
) -> type[ProsecutorModelPayload] | type[DefenderModelPayload] | type[JudgeModelPayload]:
    if role == VlmRole.PROSECUTOR:
        return ProsecutorModelPayload
    if role == VlmRole.DEFENDER:
        return DefenderModelPayload
    if role == VlmRole.JUDGE:
        return JudgeModelPayload
    raise HearingModelParserInputError(HearingModelParserInputErrorCode.RESPONSE_SCOPE_MISMATCH)


def inspect_hearing_response(
    raw_response: bytes,
    *,
    request: HearingModelRequest,
    response: HearingModelResponse,
) -> HearingParseInspection:
    """Inspect exact stored bytes without yet choosing a repair request ID."""

    if not isinstance(raw_response, bytes):
        raise HearingModelParserInputError(HearingModelParserInputErrorCode.RAW_RESPONSE_NOT_BYTES)
    _validate_response_scope(request, response)
    if len(raw_response) != response.size_bytes:
        raise HearingModelParserInputError(HearingModelParserInputErrorCode.RESPONSE_SIZE_MISMATCH)
    if len(raw_response) > request.budget.max_response_bytes:
        return HearingParseInspection(
            request=request,
            response=response,
            payload=None,
            defects=(
                _malformed_defect(
                    response.response_id,
                    ProceduralReasonCode.RESPONSE_LIMIT_EXCEEDED,
                ),
            ),
            unknown_reference_attempts=(),
        )
    if hashlib.sha256(raw_response).hexdigest() != response.content_sha256:
        raise HearingModelParserInputError(
            HearingModelParserInputErrorCode.RESPONSE_CONTENT_MISMATCH
        )

    try:
        root = load_bounded_json_object(
            raw_response,
            max_depth=request.budget.max_json_depth,
            max_fields=request.budget.max_json_fields,
            max_string_chars=request.budget.max_string_chars,
        )
    except BoundedJsonError as error:
        reason = {
            BoundedJsonFailureCode.MALFORMED_JSON: ProceduralReasonCode.MALFORMED_JSON,
            BoundedJsonFailureCode.RESPONSE_LIMIT_EXCEEDED: (
                ProceduralReasonCode.RESPONSE_LIMIT_EXCEEDED
            ),
            BoundedJsonFailureCode.ROOT_NOT_OBJECT: ProceduralReasonCode.ROOT_NOT_OBJECT,
        }[error.reason_code]
        return HearingParseInspection(
            request=request,
            response=response,
            payload=None,
            defects=(_malformed_defect(response.response_id, reason),),
            unknown_reference_attempts=(),
        )

    unknown_attempts = _scan_unknown_references(root, request)
    try:
        # FrozenContractModel already enables strict scalar validation.  Do not
        # pass Pydantic's call-level ``strict=True`` here: in JSON mode that
        # would incorrectly reject JSON arrays for immutable tuple fields.
        payload = _payload_model(request.role).model_validate_json(raw_response)
    except ValidationError as error:
        return HearingParseInspection(
            request=request,
            response=response,
            payload=None,
            defects=_classify_validation_errors(error, response_id=response.response_id),
            unknown_reference_attempts=unknown_attempts,
        )
    return HearingParseInspection(
        request=request,
        response=response,
        payload=payload,
        defects=(),
        unknown_reference_attempts=unknown_attempts,
    )


def finalize_hearing_parse(
    inspection: HearingParseInspection,
    *,
    parser_version: str = STRICT_HEARING_MODEL_PARSER_VERSION,
    repair_request_id: str | None = None,
) -> HearingModelParseResult:
    """Create the content-addressed receipt after repair identity is known."""

    request = inspection.request
    response = inspection.response
    payload = inspection.payload
    if payload is not None:
        if repair_request_id is not None:
            raise HearingModelParserInputError(
                HearingModelParserInputErrorCode.REPAIR_REQUEST_ID_FORBIDDEN
            )
        status = ModelParseStatus.PARSED
    elif request.attempt_index == 0:
        if repair_request_id is None:
            raise HearingModelParserInputError(
                HearingModelParserInputErrorCode.REPAIR_REQUEST_ID_REQUIRED
            )
        if _SHA256.fullmatch(repair_request_id) is None:
            raise HearingModelParserInputError(
                HearingModelParserInputErrorCode.INVALID_REPAIR_REQUEST_ID
            )
        status = ModelParseStatus.REPAIR_REQUIRED
    else:
        if repair_request_id is not None:
            raise HearingModelParserInputError(
                HearingModelParserInputErrorCode.REPAIR_REQUEST_ID_FORBIDDEN
            )
        status = ModelParseStatus.INVALID_FINAL

    receipt = HearingModelParseReceipt(
        run_id=request.run_id,
        case_id=request.case_id,
        hearing_session_id=request.hearing_session_id,
        round_index=request.round_index,
        role=request.role,
        attempt_index=request.attempt_index,
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        response_id=response.response_id,
        response_content_sha256=response.content_sha256,
        parser_version=parser_version,
        output_schema_sha256=request.prompt_manifest.output_schema_sha256,
        status=status,
        defects=inspection.defects,
        unknown_reference_attempts=inspection.unknown_reference_attempts,
        parsed_payload_sha256=payload.payload_sha256 if payload is not None else None,
        repair_request_id=(
            repair_request_id if status == ModelParseStatus.REPAIR_REQUIRED else None
        ),
        manifest_id=request.manifest_id,
    )
    return HearingModelParseResult(payload=payload, receipt=receipt)


def parse_hearing_response(
    raw_response: bytes,
    *,
    request: HearingModelRequest,
    response: HearingModelResponse,
    parser_version: str = STRICT_HEARING_MODEL_PARSER_VERSION,
    repair_request_id: str | None = None,
) -> HearingModelParseResult:
    inspection = inspect_hearing_response(
        raw_response,
        request=request,
        response=response,
    )
    return finalize_hearing_parse(
        inspection,
        parser_version=parser_version,
        repair_request_id=repair_request_id,
    )


__all__ = [
    "STRICT_HEARING_MODEL_PARSER_VERSION",
    "HearingModelParseResult",
    "HearingModelParserInputError",
    "HearingModelParserInputErrorCode",
    "HearingParseInspection",
    "finalize_hearing_parse",
    "inspect_hearing_response",
    "parse_hearing_response",
]
