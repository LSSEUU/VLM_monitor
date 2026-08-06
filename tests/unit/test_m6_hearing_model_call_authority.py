from __future__ import annotations

import copy
import hashlib
import sqlite3
from dataclasses import replace
from typing import Any

import pytest

from labcourt.adapters.storage.readonly_m6_hearing_model_calls import (
    ReadonlyM6HearingModelCallAuthorityRepository,
)
from labcourt.adapters.storage.readonly_sqlite import readonly_sqlite_snapshot
from labcourt.application.m6_hearing_model_call_authority import (
    M6HearingModelCallAuthorityError,
    M6HearingModelCallAuthorityErrorCode,
    assemble_m6_locked_hearing_model_calls,
    derive_m6_hearing_model_call_authority_root,
    resolve_m6_locked_hearing_model_responses,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case
from labcourt.contracts.enums import (
    ArtifactKind,
    ModelParseStatus,
    ProceduralDefectCode,
    ProceduralDefectOrigin,
    ProceduralField,
    ProceduralReasonCode,
)
from labcourt.contracts.hearing import (
    HearingModelCacheEntry,
    HearingModelParseReceipt,
    HearingModelRequest,
    HearingModelResponse,
    HearingRoleOutput,
    HearingUsageReceipt,
    derive_hearing_model_response_id,
)
from labcourt.contracts.m6_replay_locked import (
    M6LockedModelCallLayer,
    M6LockedModelCallResultKind,
    M6LockedModelRole,
)
from labcourt.contracts.storage import ArtifactRef
from labcourt.contracts.verdicts import ProceduralDefect
from labcourt.ports.m6_model_calls import (
    M6M4ModelCacheAuthorityDocument,
    M6M4ModelCallAuthoritySnapshot,
    M6M4ModelParseReceiptAuthorityDocument,
    M6M4ModelRequestAuthorityDocument,
    M6M4ModelResponseAuthorityDocument,
    M6M4ModelUsageAuthorityDocument,
    M6M4RoleOutputAuthorityDocument,
)
from tests.integration.test_m3_sqlite_repository import RUN_ID
from tests.integration.test_m4_replay_authority_snapshot import _one_role_call
from tests.integration.test_m4_sqlite_hearing_retry import _provider_outage_seed


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _document_sha256(document: object) -> str:
    assert hasattr(document, "model_dump")
    raw = canonical_json(document.model_dump(mode="json"))
    return _sha(raw)


@pytest.fixture(scope="module")
def response_authority(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[Case, M6M4ModelCallAuthoritySnapshot]:
    started = _one_role_call(tmp_path_factory.mktemp("m6-m4-model-call-unit"))
    source = started.repository.load_case(RUN_ID, started.session.case_id)
    with readonly_sqlite_snapshot(started.database) as private_snapshot:
        authority = ReadonlyM6HearingModelCallAuthorityRepository(private_snapshot).load_authority(
            source.case
        )
    return source.case, authority


@pytest.fixture(scope="module")
def failure_authority(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[Case, M6M4ModelCallAuthoritySnapshot]:
    seed = _provider_outage_seed(tmp_path_factory.mktemp("m6-m4-model-failure-unit"))
    with sqlite3.connect(seed.database) as connection:
        row = connection.execute(
            "SELECT case_id FROM m4_hearings WHERE run_id = ? AND hearing_id = ?",
            (RUN_ID, seed.hearing_id),
        ).fetchone()
    assert row is not None and isinstance(row[0], str)
    source = seed.repository.load_case(RUN_ID, row[0])
    with readonly_sqlite_snapshot(seed.database) as private_snapshot:
        authority = ReadonlyM6HearingModelCallAuthorityRepository(private_snapshot).load_authority(
            source.case
        )
    return source.case, authority


def _reroot(
    snapshot: M6M4ModelCallAuthoritySnapshot,
    **changes: Any,
) -> M6M4ModelCallAuthoritySnapshot:
    updated = replace(snapshot, **changes)
    root = derive_m6_hearing_model_call_authority_root(
        source_identity_sha256=updated.source_identity_sha256,
        run_id=updated.run_id,
        case_id=updated.case_id,
        manifest_id=updated.manifest_id,
        m4_replay_authority_root_sha256=updated.m4_replay_authority_root_sha256,
        requests=updated.requests,
        responses=updated.responses,
        caches=updated.caches,
        usages=updated.usages,
        parse_receipts=updated.parse_receipts,
        role_outputs=updated.role_outputs,
        failures=updated.failures,
    )
    return replace(updated, model_call_authority_root_sha256=root)


def _error_code(
    source_case: Case,
    snapshot: M6M4ModelCallAuthoritySnapshot,
) -> M6HearingModelCallAuthorityErrorCode:
    with pytest.raises(M6HearingModelCallAuthorityError) as raised:
        assemble_m6_locked_hearing_model_calls(
            source_case=source_case,
            snapshot=snapshot,
        )
    return raised.value.code


def _response_document(response: HearingModelResponse) -> M6M4ModelResponseAuthorityDocument:
    return M6M4ModelResponseAuthorityDocument(
        response=response,
        document_sha256=_document_sha256(response),
    )


def _usage_document(receipt: HearingUsageReceipt) -> M6M4ModelUsageAuthorityDocument:
    return M6M4ModelUsageAuthorityDocument(
        receipt=receipt,
        document_sha256=_document_sha256(receipt),
    )


def _coherent_snapshot_for_request(
    snapshot: M6M4ModelCallAuthoritySnapshot,
    request: HearingModelRequest,
) -> M6M4ModelCallAuthoritySnapshot:
    original_response = snapshot.responses[0].response
    response_content = original_response.content_sha256
    response_id = derive_hearing_model_response_id(
        request.run_id,
        request.request_id,
        response_content,
    )
    response_payload = original_response.model_dump(mode="json", exclude_computed_fields=True)
    response_payload.update(
        {
            "run_id": request.run_id,
            "case_id": request.case_id,
            "hearing_session_id": request.hearing_session_id,
            "round_index": request.round_index,
            "prior_acquisition_rounds": request.prior_acquisition_rounds,
            "prior_rework_rounds": request.prior_rework_rounds,
            "current_evidence_pack_id": request.current_evidence_pack_id,
            "current_evidence_pack_version": request.current_evidence_pack_version,
            "role": request.role,
            "attempt_index": request.attempt_index,
            "request_id": request.request_id,
            "request_sha256": request.request_sha256,
            "cache_key": request.cache_key,
            "raw_response_ref": f"{request.run_id}/model_responses/{response_id}.json",
            "model_manifest_id": request.model_manifest_id,
            "manifest_id": request.manifest_id,
        }
    )
    response = HearingModelResponse.model_validate(response_payload)
    cache = HearingModelCacheEntry(
        run_id=request.run_id,
        case_id=request.case_id,
        hearing_session_id=request.hearing_session_id,
        round_index=request.round_index,
        role=request.role,
        current_evidence_pack_id=request.current_evidence_pack_id,
        current_evidence_pack_version=request.current_evidence_pack_version,
        cache_key=request.cache_key,
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        response_id=response.response_id,
        response_content_sha256=response.content_sha256,
        model_manifest_id=request.model_manifest_id,
        prompt_manifest_id=request.prompt_manifest.prompt_manifest_id,
        output_schema_sha256=request.prompt_manifest.output_schema_sha256,
        manifest_id=request.manifest_id,
    )
    original_parse = snapshot.parse_receipts[0].receipt
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
        parser_version=original_parse.parser_version,
        output_schema_sha256=request.prompt_manifest.output_schema_sha256,
        status=ModelParseStatus.PARSED,
        parsed_payload_sha256=snapshot.role_outputs[0].output.payload.payload_sha256,
        manifest_id=request.manifest_id,
    )
    request_ref = ArtifactRef(
        kind=ArtifactKind.MODEL_REQUEST,
        artifact_id=request.request_id,
    )
    response_ref = ArtifactRef(
        kind=ArtifactKind.MODEL_RESPONSE,
        artifact_id=response.response_id,
    )
    usage = HearingUsageReceipt(
        run_id=request.run_id,
        case_id=request.case_id,
        hearing_session_id=request.hearing_session_id,
        round_index=request.round_index,
        role=request.role,
        request_ref=request_ref,
        response_ref=response_ref,
        input_images=len(request.media),
        input_pixels=sum(item.width * item.height for item in request.media),
        input_tokens=response.input_tokens,
        output_tokens=response.output_tokens,
        latency_ms=response.latency_ms,
        retry_count=snapshot.usages[0].receipt.retry_count,
        estimated_cost=request.budget.estimate_cost(
            input_tokens=response.input_tokens,
            output_tokens=response.output_tokens,
        ),
        manifest_id=request.manifest_id,
    )
    parse_ref = ArtifactRef(
        kind=ArtifactKind.MODEL_PARSE_RECEIPT,
        artifact_id=receipt.parse_receipt_id,
    )
    output_payload = snapshot.role_outputs[0].output.model_dump(
        mode="python", exclude_computed_fields=True
    )
    output_payload.update(
        {
            "run_id": request.run_id,
            "case_id": request.case_id,
            "hearing_session_id": request.hearing_session_id,
            "round_index": request.round_index,
            "prior_acquisition_rounds": request.prior_acquisition_rounds,
            "prior_rework_rounds": request.prior_rework_rounds,
            "current_evidence_pack_id": request.current_evidence_pack_id,
            "current_evidence_pack_version": request.current_evidence_pack_version,
            "prompt_manifest": request.prompt_manifest,
            "model_manifest_id": request.model_manifest_id,
            "request_ref": request_ref,
            "response_ref": response_ref,
            "parse_receipt_ref": parse_ref,
            "prosecutor_output_id": (
                request.prosecutor_output_ref.artifact_id
                if request.prosecutor_output_ref is not None
                else None
            ),
            "defender_output_id": (
                request.defender_output_ref.artifact_id
                if request.defender_output_ref is not None
                else None
            ),
            "precedent_retrieval_degraded": request.precedent_retrieval_degraded,
            "precedent_retrieval_receipt_id": request.precedent_retrieval_receipt_id,
            "precedent_retrieval_receipt_sha256": (request.precedent_retrieval_receipt_sha256),
            "initial_trigger_review_ref": request.initial_trigger_review_ref,
            "initial_defect_codes": request.initial_defect_codes,
            "rework_review_ref": request.rework_review_ref,
            "rework_defect_codes": request.rework_defect_codes,
            "manifest_id": request.manifest_id,
        }
    )
    output = HearingRoleOutput.model_validate(output_payload)
    return _reroot(
        snapshot,
        requests=(
            M6M4ModelRequestAuthorityDocument(
                request=request,
                document_sha256=_document_sha256(request),
            ),
        ),
        responses=(_response_document(response),),
        caches=(
            M6M4ModelCacheAuthorityDocument(
                entry=cache,
                document_sha256=_document_sha256(cache),
            ),
        ),
        usages=(_usage_document(usage),),
        parse_receipts=(
            M6M4ModelParseReceiptAuthorityDocument(
                receipt=receipt,
                document_sha256=_document_sha256(receipt),
            ),
        ),
        role_outputs=(
            M6M4RoleOutputAuthorityDocument(
                output=output,
                document_sha256=_document_sha256(output),
            ),
        ),
        failures=(),
    )


def test_assembler_builds_stable_exact_chain_and_shared_normalized_response(
    response_authority: tuple[Case, M6M4ModelCallAuthoritySnapshot],
) -> None:
    source_case, snapshot = response_authority

    calls = assemble_m6_locked_hearing_model_calls(
        source_case=source_case,
        snapshot=snapshot,
    )
    normalized = resolve_m6_locked_hearing_model_responses(calls)

    assert tuple(item.sort_key for item in calls) == tuple(sorted(item.sort_key for item in calls))
    assert len(calls) == 1
    assert calls[0].layer == M6LockedModelCallLayer.HEARING
    assert calls[0].role == M6LockedModelRole.PROSECUTOR
    assert calls[0].result_kind == M6LockedModelCallResultKind.RESPONSE
    assert calls[0].parsed_output_ref is not None
    assert normalized[0].response_id == snapshot.responses[0].response.response_id
    assert normalized[0].raw_content_sha256 == (snapshot.responses[0].response.content_sha256)


def test_failure_closure_has_no_usage_and_rejects_injected_usage(
    failure_authority: tuple[Case, M6M4ModelCallAuthoritySnapshot],
) -> None:
    source_case, snapshot = failure_authority

    calls = assemble_m6_locked_hearing_model_calls(
        source_case=source_case,
        snapshot=snapshot,
    )

    assert len(calls) == 1
    assert calls[0].result_kind == M6LockedModelCallResultKind.FAILURE
    assert snapshot.responses == ()
    assert snapshot.caches == ()
    assert snapshot.usages == ()
    assert snapshot.parse_receipts == ()
    assert snapshot.role_outputs == ()
    request = snapshot.requests[0].request
    failure = snapshot.failures[0].authority
    injected = HearingUsageReceipt(
        run_id=request.run_id,
        case_id=request.case_id,
        hearing_session_id=request.hearing_session_id,
        round_index=request.round_index,
        role=request.role,
        request_ref=ArtifactRef(
            kind=ArtifactKind.MODEL_REQUEST,
            artifact_id=request.request_id,
        ),
        response_ref=ArtifactRef(
            kind=ArtifactKind.MODEL_RESPONSE,
            artifact_id=_sha("forged response for failed call"),
        ),
        input_images=len(request.media),
        input_pixels=sum(item.width * item.height for item in request.media),
        input_tokens=0,
        output_tokens=0,
        latency_ms=0,
        retry_count=failure.claim_takeover_count,
        estimated_cost=request.budget.estimate_cost(input_tokens=0, output_tokens=0),
        manifest_id=request.manifest_id,
    )
    crossed = _reroot(snapshot, usages=(_usage_document(injected),))

    assert (
        _error_code(source_case, crossed)
        == M6HearingModelCallAuthorityErrorCode.MODEL_CALL_RESULT_CROSSED
    )


@pytest.mark.parametrize(
    ("mutation", "expected"),
    (
        (
            lambda snapshot: _reroot(snapshot, responses=()),
            M6HearingModelCallAuthorityErrorCode.MODEL_CALL_RESULT_MISSING,
        ),
        (
            lambda snapshot: _reroot(snapshot, caches=()),
            M6HearingModelCallAuthorityErrorCode.MODEL_CACHE_MISSING,
        ),
        (
            lambda snapshot: _reroot(snapshot, usages=()),
            M6HearingModelCallAuthorityErrorCode.MODEL_USAGE_MISSING,
        ),
        (
            lambda snapshot: _reroot(snapshot, parse_receipts=()),
            M6HearingModelCallAuthorityErrorCode.PARSE_RECEIPT_MISSING,
        ),
        (
            lambda snapshot: _reroot(snapshot, role_outputs=()),
            M6HearingModelCallAuthorityErrorCode.ROLE_OUTPUT_MISSING,
        ),
        (
            lambda snapshot: _reroot(snapshot, requests=()),
            M6HearingModelCallAuthorityErrorCode.MODEL_CALL_AUTHORITY_EXTRA,
        ),
        (
            lambda snapshot: replace(
                snapshot,
                model_call_authority_root_sha256=_sha("forged call root"),
            ),
            M6HearingModelCallAuthorityErrorCode.SNAPSHOT_AUTHORITY_ROOT_INVALID,
        ),
        (
            lambda snapshot: replace(snapshot, authority_failure_count=1),
            M6HearingModelCallAuthorityErrorCode.SNAPSHOT_AUTHORITY_INVALID,
        ),
    ),
)
def test_assembler_fails_closed_on_missing_extra_or_invalid_root(
    response_authority: tuple[Case, M6M4ModelCallAuthoritySnapshot],
    mutation: object,
    expected: M6HearingModelCallAuthorityErrorCode,
) -> None:
    source_case, snapshot = response_authority
    assert callable(mutation)

    assert _error_code(source_case, mutation(snapshot)) == expected


def test_assembler_rejects_duplicate_request_response_and_usage_relations(
    response_authority: tuple[Case, M6M4ModelCallAuthoritySnapshot],
) -> None:
    source_case, snapshot = response_authority
    duplicated_request = replace(
        snapshot,
        requests=(snapshot.requests[0], snapshot.requests[0]),
    )
    assert (
        _error_code(source_case, duplicated_request)
        == M6HearingModelCallAuthorityErrorCode.MODEL_REQUEST_DUPLICATE
    )

    original = snapshot.responses[0].response
    second_content = _sha("second response for same request")
    second_response_id = derive_hearing_model_response_id(
        original.run_id,
        original.request_id,
        second_content,
    )
    payload = original.model_dump(mode="json", exclude_computed_fields=True)
    payload.update(
        {
            "content_sha256": second_content,
            "raw_response_ref": (f"{original.run_id}/model_responses/{second_response_id}.json"),
        }
    )
    second = _response_document(HearingModelResponse.model_validate(payload))
    duplicated_relation = _reroot(
        snapshot,
        responses=tuple(
            sorted(
                (*snapshot.responses, second),
                key=lambda item: item.response.response_id,
            )
        ),
    )
    assert (
        _error_code(source_case, duplicated_relation)
        == M6HearingModelCallAuthorityErrorCode.MODEL_RESPONSE_DUPLICATE
    )

    duplicated_usage = _reroot(
        snapshot,
        usages=(snapshot.usages[0], snapshot.usages[0]),
    )
    assert (
        _error_code(source_case, duplicated_usage)
        == M6HearingModelCallAuthorityErrorCode.MODEL_USAGE_DUPLICATE
    )


@pytest.mark.parametrize("mutation", ("response_ref", "estimated_cost"))
def test_assembler_cross_binds_usage_and_recomputes_cost(
    response_authority: tuple[Case, M6M4ModelCallAuthoritySnapshot],
    mutation: str,
) -> None:
    source_case, snapshot = response_authority
    original = snapshot.usages[0].receipt
    payload = original.model_dump(mode="python", exclude_computed_fields=True)
    if mutation == "response_ref":
        payload["response_ref"] = ArtifactRef(
            kind=ArtifactKind.MODEL_RESPONSE,
            artifact_id=_sha("foreign usage response"),
        )
    else:
        payload["estimated_cost"] = 0.5 if original.estimated_cost != 0.5 else 0.75
    forged = HearingUsageReceipt.model_validate(payload)
    authority = _reroot(snapshot, usages=(_usage_document(forged),))

    assert (
        _error_code(source_case, authority)
        == M6HearingModelCallAuthorityErrorCode.MODEL_USAGE_BINDING_MISMATCH
    )


def test_assembler_rejects_orphan_usage_as_extra_authority(
    response_authority: tuple[Case, M6M4ModelCallAuthoritySnapshot],
) -> None:
    source_case, snapshot = response_authority
    payload = snapshot.usages[0].receipt.model_dump(
        mode="python",
        exclude_computed_fields=True,
    )
    payload["request_ref"] = ArtifactRef(
        kind=ArtifactKind.MODEL_REQUEST,
        artifact_id=_sha("orphan usage request"),
    )
    orphan = _usage_document(HearingUsageReceipt.model_validate(payload))
    authority = _reroot(
        snapshot,
        usages=tuple(
            sorted(
                (*snapshot.usages, orphan),
                key=lambda item: item.receipt.usage_receipt_id,
            )
        ),
    )

    assert (
        _error_code(source_case, authority)
        == M6HearingModelCallAuthorityErrorCode.MODEL_CALL_AUTHORITY_EXTRA
    )


def test_assembler_revalidates_forged_nested_contracts(
    response_authority: tuple[Case, M6M4ModelCallAuthoritySnapshot],
) -> None:
    source_case, snapshot = response_authority
    forged_response = copy.deepcopy(snapshot.responses[0].response)
    object.__setattr__(forged_response, "size_bytes", -1)
    forged = replace(
        snapshot,
        responses=(replace(snapshot.responses[0], response=forged_response),),
    )

    assert (
        _error_code(source_case, forged)
        == M6HearingModelCallAuthorityErrorCode.MODEL_RESPONSE_DOCUMENT_INVALID
    )


def test_assembler_rejects_foreign_scope_before_call_projection(
    response_authority: tuple[Case, M6M4ModelCallAuthoritySnapshot],
) -> None:
    source_case, snapshot = response_authority
    original = snapshot.responses[0].response
    payload = original.model_dump(mode="json", exclude_computed_fields=True)
    payload["case_id"] = "foreign-case"
    foreign = _response_document(HearingModelResponse.model_validate(payload))
    authority = _reroot(snapshot, responses=(foreign,))

    assert (
        _error_code(source_case, authority)
        == M6HearingModelCallAuthorityErrorCode.MODEL_RESPONSE_SCOPE_MISMATCH
    )


def test_assembler_requires_request_pack_to_exist_in_source_case(
    response_authority: tuple[Case, M6M4ModelCallAuthoritySnapshot],
) -> None:
    source_case, snapshot = response_authority
    request_payload = snapshot.requests[0].request.model_dump(
        mode="json", exclude_computed_fields=True
    )
    request_payload["current_evidence_pack_id"] = _sha("self-consistent foreign pack")
    request = HearingModelRequest.model_validate(request_payload)
    authority = _coherent_snapshot_for_request(snapshot, request)

    assert (
        _error_code(source_case, authority)
        == M6HearingModelCallAuthorityErrorCode.MODEL_REQUEST_EVIDENCE_PACK_MISSING
    )


def test_attempt_one_requires_primary_repair_required_history(
    response_authority: tuple[Case, M6M4ModelCallAuthoritySnapshot],
) -> None:
    source_case, snapshot = response_authority
    primary = snapshot.requests[0].request
    request_payload = primary.model_dump(mode="python", exclude_computed_fields=True)
    request_payload.update(
        {
            "attempt_index": 1,
            "rendered_prompt_sha256": _sha("orphan repair rendered prompt"),
            "hearing_context_sha256": _sha("orphan repair context"),
            "media": (),
            "original_request_id": _sha("missing primary request"),
            "original_response_id": _sha("missing primary response"),
            "original_response_content_sha256": _sha("missing primary content"),
            "repair_context_sha256": _sha("orphan repair authority"),
            "budget": primary.budget.model_copy(update={"max_images": 0, "max_input_pixels": 0}),
        }
    )
    repair = HearingModelRequest.model_validate(request_payload)
    authority = _coherent_snapshot_for_request(snapshot, repair)

    assert (
        _error_code(source_case, authority)
        == M6HearingModelCallAuthorityErrorCode.REPAIR_HISTORY_MISSING
    )


def test_assembler_revalidates_forged_source_case_before_scope_use(
    response_authority: tuple[Case, M6M4ModelCallAuthoritySnapshot],
) -> None:
    source_case, snapshot = response_authority
    forged = copy.deepcopy(source_case)
    object.__setattr__(forged, "run_id", "invalid run id")

    assert _error_code(forged, snapshot) == M6HearingModelCallAuthorityErrorCode.SOURCE_CASE_INVALID


@pytest.mark.parametrize(
    "updates",
    (
        {"hearing_session_id": "e" * 64},
        {"role": "DEFENDER"},
        {"attempt_index": 1},
        {"round_index": 2, "prior_acquisition_rounds": 1},
        {"current_evidence_pack_id": "d" * 64},
    ),
)
def test_response_cross_binds_role_attempt_cycle_session_and_pack(
    response_authority: tuple[Case, M6M4ModelCallAuthoritySnapshot],
    updates: dict[str, object],
) -> None:
    source_case, snapshot = response_authority
    payload = snapshot.responses[0].response.model_dump(mode="json", exclude_computed_fields=True)
    payload.update(updates)
    response = HearingModelResponse.model_validate(payload)
    authority = _reroot(snapshot, responses=(_response_document(response),))

    assert (
        _error_code(source_case, authority)
        == M6HearingModelCallAuthorityErrorCode.MODEL_RESPONSE_BINDING_MISMATCH
    )


@pytest.mark.parametrize(
    ("group", "expected"),
    (
        (
            "response",
            M6HearingModelCallAuthorityErrorCode.MODEL_RESPONSE_BINDING_MISMATCH,
        ),
        (
            "cache",
            M6HearingModelCallAuthorityErrorCode.MODEL_CACHE_BINDING_MISMATCH,
        ),
        (
            "parse",
            M6HearingModelCallAuthorityErrorCode.PARSE_RECEIPT_BINDING_MISMATCH,
        ),
        (
            "output",
            M6HearingModelCallAuthorityErrorCode.ROLE_OUTPUT_BINDING_MISMATCH,
        ),
    ),
)
def test_assembler_cross_binds_cycle_pack_cache_parse_and_output(
    response_authority: tuple[Case, M6M4ModelCallAuthoritySnapshot],
    group: str,
    expected: M6HearingModelCallAuthorityErrorCode,
) -> None:
    source_case, snapshot = response_authority
    if group == "response":
        payload = snapshot.responses[0].response.model_dump(
            mode="json", exclude_computed_fields=True
        )
        payload["current_evidence_pack_id"] = _sha("foreign pack")
        response = HearingModelResponse.model_validate(payload)
        authority = _reroot(snapshot, responses=(_response_document(response),))
    elif group == "cache":
        payload = snapshot.caches[0].entry.model_dump(mode="json", exclude_computed_fields=True)
        payload["response_content_sha256"] = _sha("foreign response content")
        cache = HearingModelCacheEntry.model_validate(payload)
        authority = _reroot(
            snapshot,
            caches=(
                M6M4ModelCacheAuthorityDocument(
                    entry=cache,
                    document_sha256=_document_sha256(cache),
                ),
            ),
        )
    elif group == "parse":
        payload = snapshot.parse_receipts[0].receipt.model_dump(
            mode="json", exclude_computed_fields=True
        )
        payload["output_schema_sha256"] = _sha("foreign schema")
        receipt = HearingModelParseReceipt.model_validate(payload)
        authority = _reroot(
            snapshot,
            parse_receipts=(
                M6M4ModelParseReceiptAuthorityDocument(
                    receipt=receipt,
                    document_sha256=_document_sha256(receipt),
                ),
            ),
        )
    else:
        payload = snapshot.role_outputs[0].output.model_dump(
            mode="json", exclude_computed_fields=True
        )
        payload["precedent_retrieval_receipt_sha256"] = _sha("foreign retrieval")
        output = HearingRoleOutput.model_validate(payload)
        authority = _reroot(
            snapshot,
            role_outputs=(
                M6M4RoleOutputAuthorityDocument(
                    output=output,
                    document_sha256=_document_sha256(output),
                ),
            ),
        )

    assert _error_code(source_case, authority) == expected


def test_failed_parse_response_chain_does_not_fabricate_role_output(
    response_authority: tuple[Case, M6M4ModelCallAuthoritySnapshot],
) -> None:
    source_case, snapshot = response_authority
    response = snapshot.responses[0].response
    parse_payload = snapshot.parse_receipts[0].receipt.model_dump(
        mode="json", exclude_computed_fields=True
    )
    parse_payload.update(
        {
            "status": ModelParseStatus.REPAIR_REQUIRED,
            "defects": (
                ProceduralDefect(
                    code=ProceduralDefectCode.MALFORMED_STRUCTURE,
                    origin=ProceduralDefectOrigin.PARSER,
                    reason_code=ProceduralReasonCode.MALFORMED_JSON,
                    artifact_ref=ArtifactRef(
                        kind=ArtifactKind.MODEL_RESPONSE,
                        artifact_id=response.response_id,
                    ),
                    field=ProceduralField.JSON_ROOT,
                ),
            ),
            "parsed_payload_sha256": None,
            "repair_request_id": _sha("future repair request"),
        }
    )
    receipt = HearingModelParseReceipt.model_validate(parse_payload)
    authority = _reroot(
        snapshot,
        parse_receipts=(
            M6M4ModelParseReceiptAuthorityDocument(
                receipt=receipt,
                document_sha256=_document_sha256(receipt),
            ),
        ),
        role_outputs=(),
    )

    calls = assemble_m6_locked_hearing_model_calls(
        source_case=source_case,
        snapshot=authority,
    )

    assert len(calls) == 1
    assert calls[0].result_kind == M6LockedModelCallResultKind.RESPONSE
    assert calls[0].parsed_output_ref is None
    assert len(resolve_m6_locked_hearing_model_responses(calls)) == 1


def test_assembler_rejects_orphan_response_as_extra_authority(
    response_authority: tuple[Case, M6M4ModelCallAuthoritySnapshot],
) -> None:
    source_case, snapshot = response_authority
    original = snapshot.responses[0].response
    payload = original.model_dump(mode="json", exclude_computed_fields=True)
    orphan_request_id = _sha("orphan request")
    orphan_content = _sha("orphan content")
    orphan_response_id = derive_hearing_model_response_id(
        original.run_id,
        orphan_request_id,
        orphan_content,
    )
    payload.update(
        {
            "request_id": orphan_request_id,
            "request_sha256": _sha("orphan request document"),
            "cache_key": _sha("orphan cache"),
            "content_sha256": orphan_content,
            "raw_response_ref": (f"{original.run_id}/model_responses/{orphan_response_id}.json"),
        }
    )
    orphan = _response_document(HearingModelResponse.model_validate(payload))
    authority = _reroot(
        snapshot,
        responses=tuple(
            sorted(
                (*snapshot.responses, orphan),
                key=lambda item: item.response.response_id,
            )
        ),
    )

    assert (
        _error_code(source_case, authority)
        == M6HearingModelCallAuthorityErrorCode.MODEL_CALL_AUTHORITY_EXTRA
    )
