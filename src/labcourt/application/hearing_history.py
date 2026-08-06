"""Reconstruct trusted M4 provider-call history from immutable artifacts."""

from __future__ import annotations

from enum import StrEnum
from typing import NoReturn

from labcourt.contracts.enums import ArtifactKind, ModelParseStatus, VlmRole
from labcourt.contracts.hearing import (
    HearingModelParseReceipt,
    HearingModelRequest,
    HearingModelResponse,
    HearingRecord,
    HearingUsageReceipt,
)
from labcourt.contracts.storage import ArtifactRef
from labcourt.domain.evidence_authority import HearingEvidenceGrant
from labcourt.domain.hearing_fsm import (
    HearingCallClosure,
    HearingCallTrace,
    HearingTransitionError,
)
from labcourt.domain.procedural_gate import ArtifactBounds
from labcourt.exceptions import ContractViolation


class HearingHistoryBuildFailureCode(StrEnum):
    """Stable reconstruction failures without provider-authored text."""

    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    ARTIFACT_SET_MISMATCH = "ARTIFACT_SET_MISMATCH"
    CALL_BINDING_MISMATCH = "CALL_BINDING_MISMATCH"
    REPAIR_CHAIN_INVALID = "REPAIR_CHAIN_INVALID"
    EVIDENCE_GRANT_INVALID = "EVIDENCE_GRANT_INVALID"


class HearingHistoryBuildError(ContractViolation):
    """Persisted M4 artifacts cannot form one complete logical call history."""

    def __init__(self, reason_code: HearingHistoryBuildFailureCode) -> None:
        if not isinstance(reason_code, HearingHistoryBuildFailureCode):
            raise TypeError("reason_code must be a HearingHistoryBuildFailureCode")
        self.reason_code = reason_code
        super().__init__(f"hearing history build failed: {reason_code.value}")


def _fail(code: HearingHistoryBuildFailureCode) -> NoReturn:
    raise HearingHistoryBuildError(code)


_ROLE_ORDER = {
    VlmRole.PROSECUTOR: 0,
    VlmRole.DEFENDER: 1,
    VlmRole.JUDGE: 2,
}


def _call_sort_key(call: HearingCallClosure) -> tuple[int, int, int, int, str]:
    request = call.request
    retry = request.backlog_retry_context
    return (
        request.round_index,
        _ROLE_ORDER[request.role],
        retry.retry_generation if retry is not None else 0,
        request.attempt_index,
        request.request_id,
    )


def _unique_by_id(
    values: tuple[object, ...],
    *,
    id_attribute: str,
) -> dict[str, object]:
    by_id: dict[str, object] = {}
    for value in values:
        identity = getattr(value, id_attribute, None)
        if not isinstance(identity, str) or identity in by_id:
            _fail(HearingHistoryBuildFailureCode.ARTIFACT_SET_MISMATCH)
        by_id[identity] = value
    return by_id


def _expected_ids(
    refs: tuple[ArtifactRef, ...],
    kind: ArtifactKind,
) -> set[str]:
    if any(ref.kind != kind for ref in refs):
        _fail(HearingHistoryBuildFailureCode.ARTIFACT_SET_MISMATCH)
    return {ref.artifact_id for ref in refs}


def build_hearing_call_history(
    record: HearingRecord,
    *,
    requests: tuple[HearingModelRequest, ...],
    responses: tuple[HearingModelResponse, ...],
    parse_receipts: tuple[HearingModelParseReceipt, ...],
    usage_receipts: tuple[HearingUsageReceipt, ...],
) -> tuple[HearingCallClosure, ...]:
    """Join exact record roots and validate every primary/repair chain."""

    if not isinstance(record, HearingRecord):
        raise TypeError("record must be a HearingRecord")
    typed_inputs = (
        (requests, HearingModelRequest),
        (responses, HearingModelResponse),
        (parse_receipts, HearingModelParseReceipt),
        (usage_receipts, HearingUsageReceipt),
    )
    if any(
        not isinstance(values, tuple)
        or any(not isinstance(value, expected_type) for value in values)
        for values, expected_type in typed_inputs
    ):
        _fail(HearingHistoryBuildFailureCode.INVALID_ARGUMENT)

    request_map = _unique_by_id(requests, id_attribute="request_id")
    response_map = _unique_by_id(responses, id_attribute="response_id")
    parse_map = _unique_by_id(parse_receipts, id_attribute="parse_receipt_id")
    usage_map = _unique_by_id(usage_receipts, id_attribute="usage_receipt_id")
    expected_request_ids = _expected_ids(
        record.model_request_refs,
        ArtifactKind.MODEL_REQUEST,
    )
    expected_response_ids = _expected_ids(
        record.model_response_refs,
        ArtifactKind.MODEL_RESPONSE,
    )
    expected_parse_ids = _expected_ids(
        record.parse_receipt_refs,
        ArtifactKind.MODEL_PARSE_RECEIPT,
    )
    if (
        set(request_map) != expected_request_ids
        or set(response_map) != expected_response_ids
        or set(parse_map) != expected_parse_ids
        or set(usage_map) != {receipt.usage_receipt_id for receipt in record.usage_receipts}
        or tuple(
            sorted(
                usage_receipts,
                key=lambda item: (
                    item.round_index,
                    item.role.value,
                    item.request_ref.artifact_id,
                ),
            )
        )
        != record.usage_receipts
    ):
        _fail(HearingHistoryBuildFailureCode.ARTIFACT_SET_MISMATCH)

    responses_by_request: dict[str, HearingModelResponse] = {}
    parses_by_request: dict[str, HearingModelParseReceipt] = {}
    usage_by_request: dict[str, HearingUsageReceipt] = {}
    try:
        for value in response_map.values():
            assert isinstance(value, HearingModelResponse)
            if value.request_id in responses_by_request:
                _fail(HearingHistoryBuildFailureCode.CALL_BINDING_MISMATCH)
            responses_by_request[value.request_id] = value
        for value in parse_map.values():
            assert isinstance(value, HearingModelParseReceipt)
            if value.request_id in parses_by_request:
                _fail(HearingHistoryBuildFailureCode.CALL_BINDING_MISMATCH)
            parses_by_request[value.request_id] = value
        for value in usage_map.values():
            assert isinstance(value, HearingUsageReceipt)
            request_id = value.request_ref.artifact_id
            if request_id in usage_by_request:
                _fail(HearingHistoryBuildFailureCode.CALL_BINDING_MISMATCH)
            usage_by_request[request_id] = value
    except (TypeError, ValueError):
        _fail(HearingHistoryBuildFailureCode.CALL_BINDING_MISMATCH)
    if not (
        set(responses_by_request)
        == set(parses_by_request)
        == set(usage_by_request)
        == set(request_map)
    ):
        _fail(HearingHistoryBuildFailureCode.CALL_BINDING_MISMATCH)

    calls: list[HearingCallClosure] = []
    for request_id, raw_request in request_map.items():
        assert isinstance(raw_request, HearingModelRequest)
        try:
            calls.append(
                HearingCallClosure(
                    request=raw_request,
                    response=responses_by_request[request_id],
                    parse_receipt=parses_by_request[request_id],
                    usage=usage_by_request[request_id],
                )
            )
        except (TypeError, ValueError, HearingTransitionError):
            _fail(HearingHistoryBuildFailureCode.CALL_BINDING_MISMATCH)
    history = tuple(sorted(calls, key=_call_sort_key))
    calls_by_request = {call.request.request_id: call for call in history}
    used_repairs: set[str] = set()
    for call in history:
        if call.request.attempt_index == 1:
            continue
        if call.parse_receipt.status == ModelParseStatus.REPAIR_REQUIRED:
            repair_id = call.parse_receipt.repair_request_id
            repair = calls_by_request.get(repair_id or "")
            if repair is None:
                _fail(HearingHistoryBuildFailureCode.REPAIR_CHAIN_INVALID)
            try:
                HearingCallTrace(calls=(call, repair))
            except (TypeError, ValueError, HearingTransitionError):
                _fail(HearingHistoryBuildFailureCode.REPAIR_CHAIN_INVALID)
            used_repairs.add(repair.request.request_id)
        else:
            try:
                HearingCallTrace(calls=(call,))
            except (TypeError, ValueError, HearingTransitionError):
                _fail(HearingHistoryBuildFailureCode.REPAIR_CHAIN_INVALID)
    repair_ids = {call.request.request_id for call in history if call.request.attempt_index == 1}
    if repair_ids != used_repairs:
        _fail(HearingHistoryBuildFailureCode.REPAIR_CHAIN_INVALID)
    return history


def derive_hearing_evidence_grant(
    record: HearingRecord,
    history: tuple[HearingCallClosure, ...],
) -> HearingEvidenceGrant:
    """Derive the exact union of pixel disclosures used by L5 verification."""

    if (
        not isinstance(record, HearingRecord)
        or not isinstance(history, tuple)
        or any(not isinstance(call, HearingCallClosure) for call in history)
    ):
        _fail(HearingHistoryBuildFailureCode.INVALID_ARGUMENT)
    requests: dict[str, HearingModelRequest] = {
        call.request.request_id: call.request for call in history if call.request.media
    }
    for authority in record.failure_authorities:
        if authority.disclosed_images:
            requests[authority.request.request_id] = authority.request

    refs: dict[tuple[str, str], ArtifactRef] = {}
    dimensions: dict[tuple[str, str], tuple[int, int]] = {}
    for request in requests.values():
        if (
            request.run_id != record.run_id
            or request.case_id != record.case_id
            or request.hearing_session_id != record.hearing_session_id
        ):
            _fail(HearingHistoryBuildFailureCode.EVIDENCE_GRANT_INVALID)
        refs.update({ref.sort_key: ref for ref in request.allowed_evidence_refs})
        for media in request.media:
            ref = ArtifactRef(kind=ArtifactKind.CROP, artifact_id=media.crop_id)
            candidate = (media.width, media.height)
            previous = dimensions.get(ref.sort_key)
            if previous is not None and previous != candidate:
                _fail(HearingHistoryBuildFailureCode.EVIDENCE_GRANT_INVALID)
            dimensions[ref.sort_key] = candidate
    try:
        return HearingEvidenceGrant(
            run_id=record.run_id,
            case_id=record.case_id,
            latest_evidence_pack_id=record.current_evidence_pack_id,
            latest_evidence_pack_version=record.current_evidence_pack_version,
            allowed_evidence_refs=tuple(refs[key] for key in sorted(refs)),
            artifact_bounds=tuple(
                ArtifactBounds(
                    artifact_ref=refs[key],
                    width=dimensions[key][0],
                    height=dimensions[key][1],
                )
                for key in sorted(dimensions)
            ),
        )
    except (KeyError, TypeError, ValueError):
        _fail(HearingHistoryBuildFailureCode.EVIDENCE_GRANT_INVALID)


__all__ = [
    "HearingHistoryBuildError",
    "HearingHistoryBuildFailureCode",
    "build_hearing_call_history",
    "derive_hearing_evidence_grant",
]
