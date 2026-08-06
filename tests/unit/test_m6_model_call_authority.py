from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime

import pytest

from labcourt.application.m6_model_call_authority import (
    M6ModelCallAuthorityError,
    M6ModelCallAuthorityErrorCode,
    assemble_m6_locked_screening_model_calls,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case, UsageSummary
from labcourt.contracts.enums import (
    ArtifactKind,
    BacklogReasonCode,
    BacklogStatus,
    CaseStatus,
)
from labcourt.contracts.evidence import EvidencePack
from labcourt.contracts.m6_replay_locked import M6LockedModelCallResultKind
from labcourt.contracts.model_call_failures import (
    ModelCallFailureAuthority,
    ModelCallFailureClosureKind,
    VLMDeliveryCertainty,
    VLMProviderFailureCode,
)
from labcourt.contracts.screening import (
    ModelCacheEntry,
    VLMCallRequest,
    VLMRequest,
    VLMResponse,
    derive_model_response_id,
)
from labcourt.contracts.storage import ArtifactRef, ClosureReport
from labcourt.domain.m6_semantic_projection import resolve_m6_locked_model_responses
from labcourt.ports.m6_model_calls import (
    M6M3ModelCacheAuthorityDocument,
    M6M3ModelCallAuthoritySnapshot,
    M6M3ModelCallFailureAuthorityDocument,
    M6M3ModelParseReceiptAuthorityDocument,
    M6M3ModelRequestAuthorityDocument,
    M6M3ModelResponseAuthorityDocument,
    M6M3ModelUsageAuthorityDocument,
    M6M3ParsedOutputAuthorityDocument,
)
from tests.integration.test_m3_sqlite_repository import (
    RUN_ID,
    _draft,
    _parsed,
    _parsed_receipt,
    _request,
    _response,
)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _document_sha256(document: object) -> str:
    assert hasattr(document, "model_dump")
    raw = canonical_json(document.model_dump(mode="json"))  # type: ignore[attr-defined]
    return _sha(raw)


def _source_case() -> tuple[Case, object]:
    draft = _draft(version=1, complete=True)
    closure = ClosureReport(
        run_id=RUN_ID,
        root_ref=ArtifactRef(kind=ArtifactKind.CASE, artifact_id=draft.case_id),
        manifest_id=draft.manifest_id,
        input_sha256=draft.closure_input_sha256,
        checked_refs=draft.expected_closure_refs(),
    )
    pack = EvidencePack.model_validate(
        {
            **draft.model_dump(mode="json", exclude_computed_fields=True),
            "closure_report": closure.model_dump(mode="json"),
        }
    )
    case = Case(
        run_id=RUN_ID,
        status=CaseStatus.EVIDENCE_READY,
        event=pack.event,
        evidence_packs=(pack,),
        manifest_id=pack.manifest_id,
    )
    return case, pack


def _cache_entry(request: object, response: object) -> ModelCacheEntry:
    return ModelCacheEntry(
        run_id=response.run_id,  # type: ignore[attr-defined]
        case_id=response.case_id,  # type: ignore[attr-defined]
        evidence_pack_id=response.evidence_pack_id,  # type: ignore[attr-defined]
        evidence_pack_version=response.evidence_pack_version,  # type: ignore[attr-defined]
        cache_key=response.cache_key,  # type: ignore[attr-defined]
        request_id=response.request_id,  # type: ignore[attr-defined]
        request_sha256=response.request_sha256,  # type: ignore[attr-defined]
        response_id=response.response_id,  # type: ignore[attr-defined]
        response_content_sha256=response.content_sha256,  # type: ignore[attr-defined]
        model_manifest_id=response.model_manifest_id,  # type: ignore[attr-defined]
        prompt_manifest_id=request.prompt_manifest.prompt_manifest_id,  # type: ignore[attr-defined]
        output_schema_sha256=request.prompt_manifest.output_schema_sha256,  # type: ignore[attr-defined]
        manifest_id=response.manifest_id,  # type: ignore[attr-defined]
    )


def _usage_document(
    request: VLMCallRequest,
    response: VLMResponse,
) -> M6M3ModelUsageAuthorityDocument:
    usage = UsageSummary(
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
    return M6M3ModelUsageAuthorityDocument(
        usage=usage,
        request_id=request.request_id,
        response_id=response.response_id,
        case_id=request.case_id,
        case_revision=1,
        consumer_kind="SCREENING_RESULT",
        consumer_id=_sha("screening-consumer"),
        accounted_at="2026-08-03T08:00:00.000000Z",
        document_sha256=_document_sha256(usage),
    )


def _response_snapshot() -> tuple[Case, M6M3ModelCallAuthoritySnapshot]:
    source_case, pack = _source_case()
    request = _request(pack)  # type: ignore[arg-type]
    response = _response(
        request,
        content_sha256="a" * 64,
        input_tokens=11,
        output_tokens=7,
        latency_ms=19,
    )
    output = _parsed(request, response)
    receipt = _parsed_receipt(request, response, output)
    cache = _cache_entry(request, response)
    snapshot = M6M3ModelCallAuthoritySnapshot(
        source_identity_sha256=_sha("m3-private-snapshot"),
        run_id=source_case.run_id,
        case_id=source_case.case_id,
        manifest_id=source_case.manifest_id,
        requests=(
            M6M3ModelRequestAuthorityDocument(
                request=request,
                document_sha256=_document_sha256(request),
            ),
        ),
        responses=(
            M6M3ModelResponseAuthorityDocument(
                response=response,
                document_sha256=_document_sha256(response),
            ),
        ),
        caches=(
            M6M3ModelCacheAuthorityDocument(
                request=request,
                request_document_sha256=_document_sha256(request),
                entry=cache,
                document_sha256=_document_sha256(cache),
            ),
        ),
        parse_receipts=(
            M6M3ModelParseReceiptAuthorityDocument(
                receipt=receipt,
                document_sha256=_document_sha256(receipt),
            ),
        ),
        parsed_outputs=(
            M6M3ParsedOutputAuthorityDocument(
                output=output,
                document_sha256=_document_sha256(output),
            ),
        ),
        failures=(),
        usages=(_usage_document(request, response),),
    )
    return source_case, snapshot


def _failure_document(
    request_document: M6M3ModelRequestAuthorityDocument,
) -> M6M3ModelCallFailureAuthorityDocument:
    request = request_document.request
    authority = ModelCallFailureAuthority(
        run_id=request.run_id,
        request=request,
        claim_owner_sha256="b" * 64,
        claim_lease_expires_at=datetime(2026, 8, 3, 8, 30, tzinfo=UTC),
        claim_takeover_count=0,
        failure_code=VLMProviderFailureCode.PROVIDER_OUTAGE,
        delivery_certainty=VLMDeliveryCertainty.DEFINITELY_NOT_SENT,
        backlog_reason_code=BacklogReasonCode.PROVIDER_UNAVAILABLE,
        backlog_item_id="c" * 64,
        backlog_version=1,
        backlog_status=BacklogStatus.PENDING,
        backlog_attempt_count=0,
        retry_generation=0,
        closure_kind=ModelCallFailureClosureKind.INITIAL_BACKLOG,
        closure_case_revision=2,
        closure_audit_sequence=3,
        closure_audit_entry_hash="d" * 64,
        manifest_id=request.manifest_id,
        recorded_at=datetime(2026, 8, 3, 8, 10, tzinfo=UTC),
    )
    return M6M3ModelCallFailureAuthorityDocument(
        authority=authority,
        document_sha256=_document_sha256(authority),
    )


def _error_code(
    source_case: Case,
    snapshot: M6M3ModelCallAuthoritySnapshot,
) -> M6ModelCallAuthorityErrorCode:
    with pytest.raises(M6ModelCallAuthorityError) as raised:
        assemble_m6_locked_screening_model_calls(
            source_case=source_case,
            snapshot=snapshot,
        )
    return raised.value.code


def _with_foreign_response(
    snapshot: M6M3ModelCallAuthoritySnapshot,
) -> M6M3ModelCallAuthoritySnapshot:
    foreign = snapshot.responses[0].response.model_copy(update={"case_id": "foreign-case"})
    return replace(
        snapshot,
        responses=(
            M6M3ModelResponseAuthorityDocument(
                response=foreign,
                document_sha256=_document_sha256(foreign),
            ),
        ),
    )


def _with_extra_response(
    snapshot: M6M3ModelCallAuthoritySnapshot,
) -> M6M3ModelCallAuthoritySnapshot:
    source = snapshot.responses[0].response
    request_id = "e" * 64
    response_id = derive_model_response_id(
        source.run_id,
        request_id,
        source.content_sha256,
    )
    extra = snapshot.responses[0].response.model_copy(
        update={
            "request_id": request_id,
            "request_sha256": "f" * 64,
            "cache_key": "0" * 64,
            "raw_response_ref": f"{source.run_id}/model_responses/{response_id}.json",
        }
    )
    documents = (
        *snapshot.responses,
        M6M3ModelResponseAuthorityDocument(
            response=extra,
            document_sha256=_document_sha256(extra),
        ),
    )
    return replace(
        snapshot,
        responses=tuple(sorted(documents, key=lambda item: item.response.response_id)),
    )


def _with_cache_binding_mismatch(
    snapshot: M6M3ModelCallAuthoritySnapshot,
) -> M6M3ModelCallAuthoritySnapshot:
    entry = snapshot.caches[0].entry.model_copy(update={"response_id": "e" * 64})
    return replace(
        snapshot,
        caches=(
            replace(
                snapshot.caches[0],
                entry=entry,
                document_sha256=_document_sha256(entry),
            ),
        ),
    )


def _with_parse_binding_mismatch(
    snapshot: M6M3ModelCallAuthoritySnapshot,
) -> M6M3ModelCallAuthoritySnapshot:
    receipt = snapshot.parse_receipts[0].receipt.model_copy(
        update={"response_content_sha256": "e" * 64}
    )
    return replace(
        snapshot,
        parse_receipts=(
            M6M3ModelParseReceiptAuthorityDocument(
                receipt=receipt,
                document_sha256=_document_sha256(receipt),
            ),
        ),
    )


def _with_output_binding_mismatch(
    snapshot: M6M3ModelCallAuthoritySnapshot,
) -> M6M3ModelCallAuthoritySnapshot:
    output = snapshot.parsed_outputs[0].output.model_copy(
        update={"response_content_sha256": "e" * 64}
    )
    return replace(
        snapshot,
        parsed_outputs=(
            M6M3ParsedOutputAuthorityDocument(
                output=output,
                document_sha256=_document_sha256(output),
            ),
        ),
    )


def test_assembler_builds_exact_response_chain_and_resolves_it() -> None:
    source_case, snapshot = _response_snapshot()

    calls = assemble_m6_locked_screening_model_calls(
        source_case=source_case,
        snapshot=snapshot,
    )
    responses = resolve_m6_locked_model_responses(calls)

    assert len(calls) == 1
    assert calls[0].result_kind == M6LockedModelCallResultKind.RESPONSE
    assert calls[0].attempt_index == 0
    assert calls[0].parsed_output_ref is not None
    assert responses[0].response_id == snapshot.responses[0].response.response_id
    assert responses[0].raw_content_sha256 == "a" * 64


def test_identical_usage_documents_remain_distinct_by_request_identity() -> None:
    source_case, snapshot = _response_snapshot()
    first_request = snapshot.requests[0].request
    assert isinstance(first_request, VLMRequest)
    second_request = first_request.model_copy(update={"revision": "screening-v2"})
    second_response = _response(
        second_request,
        content_sha256="b" * 64,
        input_tokens=11,
        output_tokens=7,
        latency_ms=19,
    )
    second_output = _parsed(second_request, second_response)
    second_receipt = _parsed_receipt(second_request, second_response, second_output)
    second_cache = _cache_entry(second_request, second_response)
    second_usage = _usage_document(second_request, second_response)
    two_call_snapshot = replace(
        snapshot,
        requests=tuple(
            sorted(
                (
                    *snapshot.requests,
                    M6M3ModelRequestAuthorityDocument(
                        request=second_request,
                        document_sha256=_document_sha256(second_request),
                    ),
                ),
                key=lambda item: item.request.request_id,
            )
        ),
        responses=tuple(
            sorted(
                (
                    *snapshot.responses,
                    M6M3ModelResponseAuthorityDocument(
                        response=second_response,
                        document_sha256=_document_sha256(second_response),
                    ),
                ),
                key=lambda item: item.response.response_id,
            )
        ),
        caches=tuple(
            sorted(
                (
                    *snapshot.caches,
                    M6M3ModelCacheAuthorityDocument(
                        request=second_request,
                        request_document_sha256=_document_sha256(second_request),
                        entry=second_cache,
                        document_sha256=_document_sha256(second_cache),
                    ),
                ),
                key=lambda item: item.entry.cache_entry_id,
            )
        ),
        parse_receipts=tuple(
            sorted(
                (
                    *snapshot.parse_receipts,
                    M6M3ModelParseReceiptAuthorityDocument(
                        receipt=second_receipt,
                        document_sha256=_document_sha256(second_receipt),
                    ),
                ),
                key=lambda item: item.receipt.parse_receipt_id,
            )
        ),
        parsed_outputs=tuple(
            sorted(
                (
                    *snapshot.parsed_outputs,
                    M6M3ParsedOutputAuthorityDocument(
                        output=second_output,
                        document_sha256=_document_sha256(second_output),
                    ),
                ),
                key=lambda item: item.output.parsed_output_id,
            )
        ),
        usages=tuple(sorted((*snapshot.usages, second_usage), key=lambda item: item.request_id)),
    )

    assert (
        two_call_snapshot.usages[0].document_sha256 == two_call_snapshot.usages[1].document_sha256
    )
    assert two_call_snapshot.usages[0].request_id != two_call_snapshot.usages[1].request_id
    assert (
        len(
            assemble_m6_locked_screening_model_calls(
                source_case=source_case,
                snapshot=two_call_snapshot,
            )
        )
        == 2
    )


def test_assembler_builds_failure_only_result() -> None:
    source_case, response_snapshot = _response_snapshot()
    request = response_snapshot.requests[0]
    snapshot = replace(
        response_snapshot,
        responses=(),
        caches=(),
        parse_receipts=(),
        parsed_outputs=(),
        failures=(_failure_document(request),),
        usages=(),
    )

    calls = assemble_m6_locked_screening_model_calls(
        source_case=source_case,
        snapshot=snapshot,
    )

    assert len(calls) == 1
    assert calls[0].result_kind == M6LockedModelCallResultKind.FAILURE
    assert calls[0].failure_ref is not None
    assert resolve_m6_locked_model_responses(calls) == ()


@pytest.mark.parametrize(
    ("mutation", "expected"),
    (
        (
            lambda snapshot: replace(snapshot, authority_failure_count=1),
            M6ModelCallAuthorityErrorCode.SNAPSHOT_AUTHORITY_INVALID,
        ),
        (
            lambda snapshot: replace(snapshot, requests=snapshot.requests * 257),
            M6ModelCallAuthorityErrorCode.MODEL_CALL_BUDGET_EXCEEDED,
        ),
        (
            lambda snapshot: replace(snapshot, usages=snapshot.usages * 257),
            M6ModelCallAuthorityErrorCode.MODEL_CALL_BUDGET_EXCEEDED,
        ),
        (
            lambda snapshot: replace(
                snapshot,
                responses=(),
                caches=(),
                parse_receipts=(),
                parsed_outputs=(),
            ),
            M6ModelCallAuthorityErrorCode.MODEL_CALL_RESULT_MISSING,
        ),
        (
            lambda snapshot: replace(snapshot, caches=()),
            M6ModelCallAuthorityErrorCode.MODEL_CACHE_MISSING,
        ),
        (
            lambda snapshot: replace(snapshot, parse_receipts=()),
            M6ModelCallAuthorityErrorCode.PARSE_RECEIPT_MISSING,
        ),
        (
            lambda snapshot: replace(snapshot, parsed_outputs=()),
            M6ModelCallAuthorityErrorCode.PARSED_OUTPUT_MISSING,
        ),
        (
            lambda snapshot: replace(snapshot, usages=()),
            M6ModelCallAuthorityErrorCode.MODEL_USAGE_MISSING,
        ),
        (
            lambda snapshot: replace(snapshot, usages=snapshot.usages * 2),
            M6ModelCallAuthorityErrorCode.MODEL_USAGE_DUPLICATE,
        ),
        (
            lambda snapshot: replace(
                snapshot,
                usages=(replace(snapshot.usages[0], case_id="foreign-case"),),
            ),
            M6ModelCallAuthorityErrorCode.MODEL_USAGE_SCOPE_MISMATCH,
        ),
        (
            lambda snapshot: replace(
                snapshot,
                usages=(replace(snapshot.usages[0], response_id="e" * 64),),
            ),
            M6ModelCallAuthorityErrorCode.MODEL_USAGE_BINDING_MISMATCH,
        ),
        (
            lambda snapshot: replace(
                snapshot,
                usages=(replace(snapshot.usages[0], request_id="e" * 64),),
            ),
            M6ModelCallAuthorityErrorCode.MODEL_USAGE_EXTRA,
        ),
        (
            lambda snapshot: replace(
                snapshot,
                usages=(
                    replace(
                        snapshot.usages[0],
                        document_sha256=_sha("forged-usage-document"),
                    ),
                ),
            ),
            M6ModelCallAuthorityErrorCode.MODEL_USAGE_DOCUMENT_INVALID,
        ),
        (
            lambda snapshot: replace(
                snapshot,
                responses=(),
                caches=(),
                parse_receipts=(),
                parsed_outputs=(),
                failures=(_failure_document(snapshot.requests[0]),),
            ),
            M6ModelCallAuthorityErrorCode.MODEL_CALL_RESULT_CROSSED,
        ),
        (
            lambda snapshot: replace(
                snapshot,
                responses=(snapshot.responses[0], snapshot.responses[0]),
            ),
            M6ModelCallAuthorityErrorCode.MODEL_RESPONSE_DUPLICATE,
        ),
        (
            lambda snapshot: replace(
                snapshot,
                failures=(_failure_document(snapshot.requests[0]),),
            ),
            M6ModelCallAuthorityErrorCode.MODEL_CALL_RESULT_CROSSED,
        ),
        (
            lambda snapshot: replace(
                snapshot,
                responses=(
                    replace(
                        snapshot.responses[0],
                        document_sha256=_sha("forged-response-document"),
                    ),
                ),
            ),
            M6ModelCallAuthorityErrorCode.MODEL_RESPONSE_DOCUMENT_INVALID,
        ),
        (
            _with_foreign_response,
            M6ModelCallAuthorityErrorCode.MODEL_RESPONSE_SCOPE_MISMATCH,
        ),
        (
            _with_extra_response,
            M6ModelCallAuthorityErrorCode.MODEL_RESPONSE_EXTRA,
        ),
        (
            _with_cache_binding_mismatch,
            M6ModelCallAuthorityErrorCode.MODEL_CACHE_BINDING_MISMATCH,
        ),
        (
            _with_parse_binding_mismatch,
            M6ModelCallAuthorityErrorCode.PARSE_RECEIPT_BINDING_MISMATCH,
        ),
        (
            _with_output_binding_mismatch,
            M6ModelCallAuthorityErrorCode.PARSED_OUTPUT_BINDING_MISMATCH,
        ),
    ),
)
def test_assembler_fails_closed_on_incomplete_or_forged_inventory(
    mutation: object,
    expected: M6ModelCallAuthorityErrorCode,
) -> None:
    source_case, snapshot = _response_snapshot()
    assert callable(mutation)

    assert _error_code(source_case, mutation(snapshot)) == expected
