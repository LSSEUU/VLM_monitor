"""Prepare the sole media-free structural repair attempt for an M3 response."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, NoReturn

from labcourt.application.model_parser import ScreeningParseInspection
from labcourt.application.screening_request import SUPPORTED_M3_PROMPT_BUNDLE_SHA256S
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.enums import (
    ArtifactKind,
    ProceduralDefectCode,
    ProceduralDefectOrigin,
    VlmCallPurpose,
    VlmRole,
)
from labcourt.contracts.m3_models import VlmCallBudget
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.screening import (
    StructureRepairRequest,
    VLMRequest,
    VLMResponse,
)
from labcourt.contracts.verdicts import DEFECT_ORDER, ProceduralDefect
from labcourt.exceptions import BudgetExceeded, LabCourtError
from labcourt.ports.prompts import (
    MAX_PROMPT_STRING_CHARS,
    MAX_PROMPT_VARIABLE_BYTES,
    PromptCatalog,
    RenderedPrompt,
)

STRUCTURE_REPAIR_PROMPT_ID: Final = "screening_structure_repair_v1"
_PARSER_DEFECT_CODES: Final = frozenset(
    {
        ProceduralDefectCode.MALFORMED_STRUCTURE,
        ProceduralDefectCode.INVALID_ENUM,
        ProceduralDefectCode.MISSING_REQUIRED_FIELD,
    }
)


class StructureRepairPreparationErrorCode(StrEnum):
    """Controlled reasons a structural repair request cannot be trusted."""

    RAW_RESPONSE_NOT_BYTES = "RAW_RESPONSE_NOT_BYTES"
    ORIGINAL_RESPONSE_BINDING_MISMATCH = "ORIGINAL_RESPONSE_BINDING_MISMATCH"
    RAW_RESPONSE_SIZE_MISMATCH = "RAW_RESPONSE_SIZE_MISMATCH"
    RAW_RESPONSE_CONTENT_MISMATCH = "RAW_RESPONSE_CONTENT_MISMATCH"
    ORIGINAL_RESPONSE_TOO_LARGE = "ORIGINAL_RESPONSE_TOO_LARGE"
    INSPECTION_NOT_REPAIRABLE = "INSPECTION_NOT_REPAIRABLE"
    INSPECTION_BINDING_MISMATCH = "INSPECTION_BINDING_MISMATCH"
    PARSE_DEFECTS_INVALID = "PARSE_DEFECTS_INVALID"
    RUN_MANIFEST_MISMATCH = "RUN_MANIFEST_MISMATCH"
    PROMPT_BUNDLE_MISMATCH = "PROMPT_BUNDLE_MISMATCH"
    OUTPUT_SCHEMA_MISMATCH = "OUTPUT_SCHEMA_MISMATCH"


class StructureRepairPreparationError(LabCourtError):
    """Expected preparation failure without provider-authored diagnostic text."""

    def __init__(self, reason_code: StructureRepairPreparationErrorCode) -> None:
        self.reason_code = reason_code
        super().__init__(f"structure repair preparation failed: {reason_code.value}")


@dataclass(frozen=True, slots=True)
class PreparedStructureRepairRequest:
    """The repair request and exact rendered prompt bytes it references."""

    request: StructureRepairRequest
    rendered_prompt: RenderedPrompt

    def __post_init__(self) -> None:
        if not isinstance(self.request, StructureRepairRequest):
            raise TypeError("request must be a StructureRepairRequest")
        if not isinstance(self.rendered_prompt, RenderedPrompt):
            raise TypeError("rendered_prompt must be a RenderedPrompt")
        if self.request.prompt_manifest != self.rendered_prompt.manifest:
            raise ValueError("repair request prompt manifest does not match rendered prompt")
        if self.request.rendered_prompt_sha256 != self.rendered_prompt.rendered_prompt_sha256:
            raise ValueError("repair request does not bind the rendered prompt bytes")


def _fail(code: StructureRepairPreparationErrorCode) -> NoReturn:
    raise StructureRepairPreparationError(code)


def _validate_argument_types(
    original_request: VLMRequest,
    original_response: VLMResponse,
    inspection: ScreeningParseInspection,
    raw_response: bytes,
    run_manifest: RunManifest,
    catalog: PromptCatalog,
) -> None:
    if not isinstance(original_request, VLMRequest):
        raise TypeError("original_request must be a VLMRequest")
    if not isinstance(original_response, VLMResponse):
        raise TypeError("original_response must be a VLMResponse")
    if not isinstance(inspection, ScreeningParseInspection):
        raise TypeError("inspection must be a ScreeningParseInspection")
    if not isinstance(raw_response, bytes):
        _fail(StructureRepairPreparationErrorCode.RAW_RESPONSE_NOT_BYTES)
    if not isinstance(run_manifest, RunManifest):
        raise TypeError("run_manifest must be a RunManifest")
    if not isinstance(catalog, PromptCatalog):
        raise TypeError("catalog must implement PromptCatalog")


def _validate_original_response(
    request: VLMRequest,
    response: VLMResponse,
    raw_response: bytes,
) -> None:
    response_binding = (
        response.purpose,
        response.attempt_index,
        response.run_id,
        response.case_id,
        response.evidence_pack_id,
        response.evidence_pack_version,
        response.request_id,
        response.request_sha256,
        response.cache_key,
        response.model_manifest_id,
        response.manifest_id,
        response.raw_response_ref,
    )
    expected_binding = (
        VlmCallPurpose.SCREENING,
        0,
        request.run_id,
        request.case_id,
        request.evidence_pack_id,
        request.evidence_pack_version,
        request.request_id,
        request.request_sha256,
        request.cache_key,
        request.model_manifest_id,
        request.manifest_id,
        f"{request.run_id}/model_responses/{response.response_id}.json",
    )
    if response_binding != expected_binding:
        _fail(StructureRepairPreparationErrorCode.ORIGINAL_RESPONSE_BINDING_MISMATCH)
    if len(raw_response) != response.size_bytes:
        _fail(StructureRepairPreparationErrorCode.RAW_RESPONSE_SIZE_MISMATCH)
    if hashlib.sha256(raw_response).hexdigest() != response.content_sha256:
        _fail(StructureRepairPreparationErrorCode.RAW_RESPONSE_CONTENT_MISMATCH)


def _validate_inspection(
    request: VLMRequest,
    response: VLMResponse,
    inspection: ScreeningParseInspection,
) -> tuple[ProceduralDefectCode, ...]:
    if inspection.payload is not None or inspection.attempt_index != 0:
        _fail(StructureRepairPreparationErrorCode.INSPECTION_NOT_REPAIRABLE)
    inspection_binding = (
        inspection.run_id,
        inspection.case_id,
        inspection.evidence_pack_id,
        inspection.evidence_pack_version,
        inspection.request_id,
        inspection.request_sha256,
        inspection.response_id,
        inspection.response_content_sha256,
        inspection.output_schema_sha256,
        inspection.manifest_id,
    )
    expected_binding = (
        request.run_id,
        request.case_id,
        request.evidence_pack_id,
        request.evidence_pack_version,
        request.request_id,
        request.request_sha256,
        response.response_id,
        response.content_sha256,
        request.prompt_manifest.output_schema_sha256,
        request.manifest_id,
    )
    if inspection_binding != expected_binding:
        _fail(StructureRepairPreparationErrorCode.INSPECTION_BINDING_MISMATCH)

    defects = inspection.defects
    if (
        not isinstance(defects, tuple)
        or not defects
        or any(not isinstance(defect, ProceduralDefect) for defect in defects)
    ):
        _fail(StructureRepairPreparationErrorCode.PARSE_DEFECTS_INVALID)
    keys = tuple(defect.sort_key for defect in defects)
    if len(keys) != len(set(keys)) or keys != tuple(sorted(keys)):
        _fail(StructureRepairPreparationErrorCode.PARSE_DEFECTS_INVALID)
    if any(
        defect.origin != ProceduralDefectOrigin.PARSER
        or defect.code not in _PARSER_DEFECT_CODES
        or defect.artifact_ref.kind != ArtifactKind.MODEL_RESPONSE
        or defect.artifact_ref.artifact_id != response.response_id
        for defect in defects
    ):
        _fail(StructureRepairPreparationErrorCode.PARSE_DEFECTS_INVALID)

    codes = inspection.defect_codes
    expected_codes = tuple(code for code in DEFECT_ORDER if code in {d.code for d in defects})
    if (
        not codes
        or codes != expected_codes
        or any(code not in _PARSER_DEFECT_CODES for code in codes)
    ):
        _fail(StructureRepairPreparationErrorCode.PARSE_DEFECTS_INVALID)
    return codes


def _validate_run_and_prompt_authority(
    request: VLMRequest,
    response: VLMResponse,
    inspection: ScreeningParseInspection,
    run_manifest: RunManifest,
    catalog: PromptCatalog,
) -> None:
    screening_model = run_manifest.models.get("screening")
    if screening_model is None:
        _fail(StructureRepairPreparationErrorCode.RUN_MANIFEST_MISMATCH)
    manifest_output_limit = run_manifest.decoding_parameters.max_output_tokens
    run_binding = (
        request.manifest_id,
        response.manifest_id,
        inspection.manifest_id,
        request.model_manifest_id,
        request.provider,
        request.model,
        request.revision,
        request.temperature,
        request.seed,
    )
    expected_run_binding = (
        run_manifest.manifest_id,
        run_manifest.manifest_id,
        run_manifest.manifest_id,
        screening_model.model_manifest_id,
        screening_model.provider,
        screening_model.model,
        screening_model.revision,
        run_manifest.decoding_parameters.temperature,
        run_manifest.decoding_parameters.seed,
    )
    if run_binding != expected_run_binding or (
        manifest_output_limit is not None
        and request.budget.max_output_tokens > manifest_output_limit
    ):
        _fail(StructureRepairPreparationErrorCode.RUN_MANIFEST_MISMATCH)

    bundle = run_manifest.prompt_bundle_sha256
    if (
        bundle not in SUPPORTED_M3_PROMPT_BUNDLE_SHA256S
        or request.prompt_manifest.prompt_bundle_sha256 != bundle
        or catalog.bundle_sha256 != bundle
    ):
        _fail(StructureRepairPreparationErrorCode.PROMPT_BUNDLE_MISMATCH)
    repair_manifest = catalog.manifest(STRUCTURE_REPAIR_PROMPT_ID)
    if request.prompt_manifest.role != VlmRole.SCREENING:
        _fail(StructureRepairPreparationErrorCode.OUTPUT_SCHEMA_MISMATCH)
    if (
        repair_manifest.role != VlmRole.STRUCTURE_REPAIR
        or repair_manifest.output_schema_sha256 != request.prompt_manifest.output_schema_sha256
        or repair_manifest.output_schema_sha256 != inspection.output_schema_sha256
    ):
        _fail(StructureRepairPreparationErrorCode.OUTPUT_SCHEMA_MISMATCH)


def _original_response_json(raw_response: bytes, response: VLMResponse) -> str:
    common: dict[str, object] = {
        "content_sha256": response.content_sha256,
        "size_bytes": response.size_bytes,
    }
    try:
        text = raw_response.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        pass
    else:
        utf8_document = canonical_json({**common, "encoding": "utf-8", "text": text})
        if (
            len(text) <= MAX_PROMPT_STRING_CHARS
            and len(utf8_document.encode("utf-8")) <= MAX_PROMPT_VARIABLE_BYTES
        ):
            return utf8_document

    encoded = base64.b64encode(raw_response).decode("ascii")
    if len(encoded) <= MAX_PROMPT_STRING_CHARS:
        encoded_payload: dict[str, object] = {"data": encoded}
    else:
        encoded_payload = {
            "data_chunks": [
                encoded[offset : offset + MAX_PROMPT_STRING_CHARS]
                for offset in range(0, len(encoded), MAX_PROMPT_STRING_CHARS)
            ]
        }
    base64_document = canonical_json(
        {
            **common,
            **encoded_payload,
            "encoding": "base64",
        }
    )
    if len(base64_document.encode("utf-8")) > MAX_PROMPT_VARIABLE_BYTES:
        _fail(StructureRepairPreparationErrorCode.ORIGINAL_RESPONSE_TOO_LARGE)
    return base64_document


def _parse_defects_json(defects: tuple[ProceduralDefect, ...]) -> str:
    unique = {(defect.code, defect.reason_code) for defect in defects}
    ordered = sorted(unique, key=lambda item: (DEFECT_ORDER.index(item[0]), item[1].value))
    return canonical_json(
        [{"code": code.value, "reason_code": reason.value} for code, reason in ordered]
    )


def _repair_budget(request: VLMRequest) -> VlmCallBudget:
    return VlmCallBudget(
        max_images=0,
        max_input_pixels=0,
        max_prompt_bytes=request.budget.max_prompt_bytes,
        max_input_tokens=request.budget.max_input_tokens,
        max_output_tokens=request.budget.max_output_tokens,
        pricing_currency=request.budget.pricing_currency,
        input_cost_per_million_tokens=(request.budget.input_cost_per_million_tokens),
        output_cost_per_million_tokens=(request.budget.output_cost_per_million_tokens),
        max_estimated_cost=request.budget.max_estimated_cost,
        max_response_bytes=request.budget.max_response_bytes,
        max_json_depth=request.budget.max_json_depth,
        max_json_fields=request.budget.max_json_fields,
        max_string_chars=request.budget.max_string_chars,
        timeout_seconds=request.budget.timeout_seconds,
        claim_completion_grace_seconds=request.budget.claim_completion_grace_seconds,
    )


def prepare_structure_repair_request(
    original_request: VLMRequest,
    original_response: VLMResponse,
    inspection: ScreeningParseInspection,
    raw_response: bytes,
    run_manifest: RunManifest,
    catalog: PromptCatalog,
) -> PreparedStructureRepairRequest:
    """Bind and render the only allowed structure-only repair attempt."""

    _validate_argument_types(
        original_request,
        original_response,
        inspection,
        raw_response,
        run_manifest,
        catalog,
    )
    _validate_original_response(original_request, original_response, raw_response)
    defect_codes = _validate_inspection(original_request, original_response, inspection)
    _validate_run_and_prompt_authority(
        original_request,
        original_response,
        inspection,
        run_manifest,
        catalog,
    )

    budget = _repair_budget(original_request)
    rendered_prompt = catalog.render(
        prompt_id=STRUCTURE_REPAIR_PROMPT_ID,
        variables={
            "original_response_json": _original_response_json(
                raw_response,
                original_response,
            ),
            "parse_defects_json": _parse_defects_json(inspection.defects),
        },
    )
    if len(rendered_prompt.utf8_bytes) > budget.max_prompt_bytes:
        raise BudgetExceeded(
            "structure repair rendered prompt exceeds the configured prompt byte budget"
        )
    request = StructureRepairRequest(
        run_id=original_request.run_id,
        case_id=original_request.case_id,
        evidence_pack_id=original_request.evidence_pack_id,
        evidence_pack_version=original_request.evidence_pack_version,
        provider_profile=original_request.provider_profile,
        provider=original_request.provider,
        model=original_request.model,
        revision=original_request.revision,
        model_manifest_id=original_request.model_manifest_id,
        execution_location=original_request.execution_location,
        prompt_manifest=rendered_prompt.manifest,
        rendered_prompt_sha256=rendered_prompt.rendered_prompt_sha256,
        original_request_id=original_request.request_id,
        original_request_sha256=original_request.request_sha256,
        original_response_id=original_response.response_id,
        original_response_sha256=original_response.content_sha256,
        parse_defect_codes=defect_codes,
        temperature=original_request.temperature,
        seed=original_request.seed,
        enable_thinking=original_request.enable_thinking,
        budget=budget,
        manifest_id=original_request.manifest_id,
    )
    return PreparedStructureRepairRequest(
        request=request,
        rendered_prompt=rendered_prompt,
    )


__all__ = [
    "STRUCTURE_REPAIR_PROMPT_ID",
    "PreparedStructureRepairRequest",
    "StructureRepairPreparationError",
    "StructureRepairPreparationErrorCode",
    "prepare_structure_repair_request",
]
