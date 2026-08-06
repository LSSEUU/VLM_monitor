"""Bind one strictly parsed hearing payload to its exact persisted call.

The parser deliberately returns provider-authored payload data without granting
it system scope.  This module is the sole pure conversion from that payload to
an authoritative :class:`HearingRoleOutput`: every identity is copied from the
request/response/parse closure and never accepted from provider JSON.
"""

from __future__ import annotations

from enum import StrEnum
from typing import NoReturn, cast

from pydantic import ValidationError

from labcourt.contracts.enums import ArtifactKind, ModelParseStatus
from labcourt.contracts.hearing import (
    DefenderModelPayload,
    HearingModelParseReceipt,
    HearingModelPayload,
    HearingModelRequest,
    HearingModelResponse,
    HearingRoleOutput,
    JudgeModelPayload,
    ProsecutorModelPayload,
)
from labcourt.contracts.storage import ArtifactRef
from labcourt.exceptions import ContractViolation


class HearingRoleOutputBuildFailureCode(StrEnum):
    """Stable, provider-text-free role-output construction failures."""

    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    REQUEST_RESPONSE_MISMATCH = "REQUEST_RESPONSE_MISMATCH"
    PARSE_RECEIPT_MISMATCH = "PARSE_RECEIPT_MISMATCH"
    PARSE_NOT_SUCCESSFUL = "PARSE_NOT_SUCCESSFUL"
    PAYLOAD_MISMATCH = "PAYLOAD_MISMATCH"
    ROLE_MISMATCH = "ROLE_MISMATCH"
    OUTPUT_INVALID = "OUTPUT_INVALID"


class HearingRoleOutputBuildError(ContractViolation):
    """The parsed provider payload cannot receive authoritative hearing scope."""

    def __init__(self, reason_code: HearingRoleOutputBuildFailureCode) -> None:
        if not isinstance(reason_code, HearingRoleOutputBuildFailureCode):
            raise TypeError("reason_code must be a HearingRoleOutputBuildFailureCode")
        self.reason_code = reason_code
        super().__init__(f"hearing role output build failed: {reason_code.value}")


def _fail(reason: HearingRoleOutputBuildFailureCode) -> NoReturn:
    raise HearingRoleOutputBuildError(reason)


def _require_exact_contracts(
    request: object,
    response: object,
    parse_receipt: object,
    payload: object,
) -> tuple[
    HearingModelRequest,
    HearingModelResponse,
    HearingModelParseReceipt,
    HearingModelPayload,
]:
    if type(request) is not HearingModelRequest:
        _fail(HearingRoleOutputBuildFailureCode.INVALID_ARGUMENT)
    if type(response) is not HearingModelResponse:
        _fail(HearingRoleOutputBuildFailureCode.INVALID_ARGUMENT)
    if type(parse_receipt) is not HearingModelParseReceipt:
        _fail(HearingRoleOutputBuildFailureCode.INVALID_ARGUMENT)
    # Do not accept a model-like provider object through structural typing.
    if type(payload) not in {
        ProsecutorModelPayload,
        DefenderModelPayload,
        JudgeModelPayload,
    }:
        _fail(HearingRoleOutputBuildFailureCode.INVALID_ARGUMENT)
    return (
        request,
        response,
        parse_receipt,
        cast(HearingModelPayload, payload),
    )


def build_hearing_role_output(
    *,
    request: HearingModelRequest,
    response: HearingModelResponse,
    parse_receipt: HearingModelParseReceipt,
    payload: HearingModelPayload,
) -> HearingRoleOutput:
    """Grant system scope to one exact, successfully parsed role payload."""

    request, response, parse_receipt, payload = _require_exact_contracts(
        request,
        response,
        parse_receipt,
        payload,
    )
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
        response.model_manifest_id,
        response.manifest_id,
    )
    if request_scope != response_scope or (
        response.request_id,
        response.request_sha256,
        response.cache_key,
    ) != (
        request.request_id,
        request.request_sha256,
        request.cache_key,
    ):
        _fail(HearingRoleOutputBuildFailureCode.REQUEST_RESPONSE_MISMATCH)

    parse_scope = (
        parse_receipt.run_id,
        parse_receipt.case_id,
        parse_receipt.hearing_session_id,
        parse_receipt.round_index,
        parse_receipt.role,
        parse_receipt.attempt_index,
        parse_receipt.manifest_id,
    )
    if parse_scope != (
        request.run_id,
        request.case_id,
        request.hearing_session_id,
        request.round_index,
        request.role,
        request.attempt_index,
        request.manifest_id,
    ) or (
        parse_receipt.request_id,
        parse_receipt.request_sha256,
        parse_receipt.response_id,
        parse_receipt.response_content_sha256,
        parse_receipt.output_schema_sha256,
    ) != (
        request.request_id,
        request.request_sha256,
        response.response_id,
        response.content_sha256,
        request.prompt_manifest.output_schema_sha256,
    ):
        _fail(HearingRoleOutputBuildFailureCode.PARSE_RECEIPT_MISMATCH)
    if parse_receipt.status != ModelParseStatus.PARSED:
        _fail(HearingRoleOutputBuildFailureCode.PARSE_NOT_SUCCESSFUL)
    if payload.role != request.role:
        _fail(HearingRoleOutputBuildFailureCode.ROLE_MISMATCH)
    if (
        parse_receipt.parsed_payload_sha256 is None
        or parse_receipt.parsed_payload_sha256 != payload.payload_sha256
    ):
        _fail(HearingRoleOutputBuildFailureCode.PAYLOAD_MISMATCH)

    prosecutor_output_id = (
        request.prosecutor_output_ref.artifact_id
        if request.prosecutor_output_ref is not None
        else None
    )
    defender_output_id = (
        request.defender_output_ref.artifact_id if request.defender_output_ref is not None else None
    )
    try:
        return HearingRoleOutput(
            run_id=request.run_id,
            case_id=request.case_id,
            hearing_session_id=request.hearing_session_id,
            round_index=request.round_index,
            prior_acquisition_rounds=request.prior_acquisition_rounds,
            prior_rework_rounds=request.prior_rework_rounds,
            current_evidence_pack_id=request.current_evidence_pack_id,
            current_evidence_pack_version=request.current_evidence_pack_version,
            prompt_manifest=request.prompt_manifest,
            model_manifest_id=request.model_manifest_id,
            request_ref=ArtifactRef(
                kind=ArtifactKind.MODEL_REQUEST,
                artifact_id=request.request_id,
            ),
            response_ref=ArtifactRef(
                kind=ArtifactKind.MODEL_RESPONSE,
                artifact_id=response.response_id,
            ),
            parse_receipt_ref=ArtifactRef(
                kind=ArtifactKind.MODEL_PARSE_RECEIPT,
                artifact_id=parse_receipt.parse_receipt_id,
            ),
            prosecutor_output_id=prosecutor_output_id,
            defender_output_id=defender_output_id,
            precedent_retrieval_degraded=request.precedent_retrieval_degraded,
            precedent_retrieval_receipt_id=request.precedent_retrieval_receipt_id,
            precedent_retrieval_receipt_sha256=(request.precedent_retrieval_receipt_sha256),
            initial_trigger_review_ref=request.initial_trigger_review_ref,
            initial_defect_codes=request.initial_defect_codes,
            rework_review_ref=request.rework_review_ref,
            rework_defect_codes=request.rework_defect_codes,
            payload=payload,
            manifest_id=request.manifest_id,
        )
    except (TypeError, ValueError, ValidationError):
        _fail(HearingRoleOutputBuildFailureCode.OUTPUT_INVALID)


__all__ = [
    "HearingRoleOutputBuildError",
    "HearingRoleOutputBuildFailureCode",
    "build_hearing_role_output",
]
