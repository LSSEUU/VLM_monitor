from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

import tests.unit.test_m4_hearing_domain as hearing_fixture
from labcourt.application import m6_model_reference_authority
from labcourt.application.m6_model_reference_authority import (
    M6ModelReferenceAuthorityError,
    M6ModelReferenceAuthorityErrorCode,
    assemble_m6_case_model_reference_authority,
    resolve_m6_fast_verdict_model_reference_bindings,
    resolve_m6_hearing_model_reference_bindings,
    resolve_m6_screening_model_reference_bindings,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case
from labcourt.contracts.enums import ArtifactKind, CaseStatus, ModelParseStatus, VlmRole
from labcourt.contracts.evidence import EvidencePack
from labcourt.contracts.hearing import HearingModelRequest, HearingRoleOutput, HearingRound
from labcourt.contracts.m4_projection import M4ProjectionArtifactKind
from labcourt.contracts.screening import (
    ModelParseReceipt,
    StructureRepairRequest,
    VLMMediaRef,
    VLMRequest,
)
from labcourt.contracts.storage import ArtifactRef
from labcourt.domain.hearing_fsm import (
    begin_hearing,
    complete_defender,
    complete_judge,
    complete_precedent_retrieval,
    complete_prosecutor,
)
from labcourt.domain.hearing_verdict_builder import build_hearing_verdict
from labcourt.domain.m6_model_reference_authority import (
    M6FastVerdictModelReferenceBinding,
)
from labcourt.domain.screening_router import FastVerdictBuilder
from labcourt.ports.m6_acquisition_authority import M6ValidatedM4ReplayAuthoritySnapshot
from labcourt.ports.m6_historical_retrieval import M6HistoricalAuthorityDocument
from labcourt.ports.m6_model_calls import (
    M6M3ModelCacheAuthorityDocument,
    M6M3ModelCallAuthoritySnapshot,
    M6M3ModelParseReceiptAuthorityDocument,
    M6M3ModelRequestAuthorityDocument,
    M6M3ModelResponseAuthorityDocument,
    M6M3ParsedOutputAuthorityDocument,
)
from tests.integration.test_m3_sqlite_repository import (
    _parsed,
    _parsed_receipt,
    _parser_defect,
    _repair_request,
    _response,
    _screening_for,
)
from tests.unit.test_m6_model_call_authority import (
    _cache_entry,
    _document_sha256,
    _response_snapshot,
    _usage_document,
)


def _screened_case(snapshot: M6M3ModelCallAuthoritySnapshot) -> Case:
    base, _ = _response_snapshot()
    primary = next(
        item.request for item in snapshot.requests if isinstance(item.request, VLMRequest)
    )
    pack_payload = base.evidence_packs[0].model_dump(mode="json", exclude_computed_fields=True)
    media_paths = {item.crop_id: item.local_path for item in primary.media}
    for collection in (
        "panorama_crops",
        "subject_crops",
        "focus_crops",
        "temporal_crops",
    ):
        for crop in pack_payload[collection]:
            crop_id = next(
                item.crop_id
                for item in base.evidence_packs[0].crops
                if item.model_dump(mode="json", exclude_computed_fields=True) == crop
            )
            if crop_id in media_paths:
                crop["local_path"] = media_paths[crop_id]
    pack = EvidencePack.model_validate(pack_payload)
    screening = _screening_for(pack, snapshot.parsed_outputs[-1].output)
    return Case.model_validate(
        {
            **base.model_dump(mode="json", exclude_computed_fields=True),
            "status": CaseStatus.SCREENED.value,
            "evidence_packs": (pack.model_dump(mode="json"),),
            "screening_results": (screening.model_dump(mode="json"),),
        }
    )


def _repair_snapshot(*, foreign_scope_ref: bool = False) -> M6M3ModelCallAuthoritySnapshot:
    case, base = _response_snapshot()
    original_primary = base.requests[0].request
    assert isinstance(original_primary, VLMRequest)
    pack = case.evidence_packs[0]
    closure_kinds = frozenset(
        {ArtifactKind.FRAME, ArtifactKind.OBJECTIVE_FACT, ArtifactKind.TOOL_RESULT}
    )
    allowed = tuple(
        sorted(
            (
                *(ref for ref in pack.expected_closure_refs() if ref.kind in closure_kinds),
                *(
                    ArtifactRef(kind=ArtifactKind.CROP, artifact_id=media.crop_id)
                    for media in original_primary.media
                ),
                *(
                    (ArtifactRef(kind=ArtifactKind.OBJECTIVE_FACT, artifact_id="future-fact"),)
                    if foreign_scope_ref
                    else ()
                ),
            ),
            key=lambda ref: ref.sort_key,
        )
    )
    primary_payload = original_primary.model_dump(mode="json", exclude_computed_fields=True)
    primary_payload["allowed_evidence_refs"] = tuple(ref.model_dump(mode="json") for ref in allowed)
    primary = VLMRequest.model_validate(primary_payload)
    first_response = _response(
        primary,
        content_sha256="a" * 64,
        input_tokens=13,
        output_tokens=3,
        latency_ms=17,
    )
    repair = _repair_request(primary, first_response)
    first_receipt = ModelParseReceipt(
        run_id=primary.run_id,
        case_id=primary.case_id,
        evidence_pack_id=primary.evidence_pack_id,
        evidence_pack_version=primary.evidence_pack_version,
        request_id=primary.request_id,
        request_sha256=primary.request_sha256,
        response_id=first_response.response_id,
        response_content_sha256=first_response.content_sha256,
        attempt_index=0,
        parser_version="strict-json-v1",
        output_schema_sha256=primary.prompt_manifest.output_schema_sha256,
        status=ModelParseStatus.REPAIR_REQUIRED,
        defects=(_parser_defect(first_response.response_id),),
        repair_request_id=repair.request_id,
        manifest_id=primary.manifest_id,
    )
    final_response = _response(
        repair,
        content_sha256="b" * 64,
        input_tokens=5,
        output_tokens=9,
        latency_ms=23,
    )
    output = _parsed(
        repair,
        final_response,
        evidence_ref=primary.allowed_evidence_refs[0],
    )
    final_receipt = _parsed_receipt(repair, final_response, output)
    requests = tuple(
        sorted(
            (
                M6M3ModelRequestAuthorityDocument(
                    request=primary,
                    document_sha256=_document_sha256(primary),
                ),
                M6M3ModelRequestAuthorityDocument(
                    request=repair,
                    document_sha256=_document_sha256(repair),
                ),
            ),
            key=lambda item: item.request.request_id,
        )
    )
    responses = tuple(
        sorted(
            (
                M6M3ModelResponseAuthorityDocument(
                    response=first_response,
                    document_sha256=_document_sha256(first_response),
                ),
                M6M3ModelResponseAuthorityDocument(
                    response=final_response,
                    document_sha256=_document_sha256(final_response),
                ),
            ),
            key=lambda item: item.response.response_id,
        )
    )
    caches = tuple(
        sorted(
            (
                M6M3ModelCacheAuthorityDocument(
                    request=primary,
                    request_document_sha256=_document_sha256(primary),
                    entry=_cache_entry(primary, first_response),
                    document_sha256=_document_sha256(_cache_entry(primary, first_response)),
                ),
                M6M3ModelCacheAuthorityDocument(
                    request=repair,
                    request_document_sha256=_document_sha256(repair),
                    entry=_cache_entry(repair, final_response),
                    document_sha256=_document_sha256(_cache_entry(repair, final_response)),
                ),
            ),
            key=lambda item: item.entry.cache_entry_id,
        )
    )
    receipts = tuple(
        sorted(
            (
                M6M3ModelParseReceiptAuthorityDocument(
                    receipt=first_receipt,
                    document_sha256=_document_sha256(first_receipt),
                ),
                M6M3ModelParseReceiptAuthorityDocument(
                    receipt=final_receipt,
                    document_sha256=_document_sha256(final_receipt),
                ),
            ),
            key=lambda item: item.receipt.parse_receipt_id,
        )
    )
    return M6M3ModelCallAuthoritySnapshot(
        source_identity_sha256=base.source_identity_sha256,
        run_id=case.run_id,
        case_id=case.case_id,
        manifest_id=case.manifest_id,
        requests=requests,
        responses=responses,
        caches=caches,
        parse_receipts=receipts,
        parsed_outputs=(
            M6M3ParsedOutputAuthorityDocument(
                output=output,
                document_sha256=_document_sha256(output),
            ),
        ),
        failures=(),
        usages=tuple(
            sorted(
                (
                    _usage_document(primary, first_response),
                    _usage_document(repair, final_response),
                ),
                key=lambda item: item.request_id,
            )
        ),
    )


def _m4_document(
    kind: M4ProjectionArtifactKind,
    artifact_id: str,
    document: object,
) -> M6HistoricalAuthorityDocument:
    assert hasattr(document, "model_dump")
    return M6HistoricalAuthorityDocument(
        kind=kind,
        artifact_id=artifact_id,
        canonical_document=canonical_json(document.model_dump(mode="json")),  # type: ignore[attr-defined]
    )


def _fast_case(snapshot: M6M3ModelCallAuthoritySnapshot) -> Case:
    case = _screened_case(snapshot)
    response_refs = tuple(
        sorted(
            (
                ArtifactRef(
                    kind=ArtifactKind.MODEL_RESPONSE,
                    artifact_id=item.receipt.response_id,
                )
                for item in snapshot.parse_receipts
            ),
            key=lambda item: item.sort_key,
        )
    )
    verdict = FastVerdictBuilder().build(
        case.screening_results[0],
        case.evidence_packs[0],
        model_response_refs=response_refs,
    )
    return Case.model_validate(
        {
            **case.model_dump(mode="json", exclude_computed_fields=True),
            "status": CaseStatus.PROCEDURAL_REVIEW.value,
            "verdicts": (verdict.model_dump(mode="json"),),
        }
    )


def _m4_case_and_snapshot(
    m3_snapshot: M6M3ModelCallAuthoritySnapshot,
    monkeypatch: pytest.MonkeyPatch,
    *,
    repair_prosecutor: bool = False,
) -> tuple[Case, M6ValidatedM4ReplayAuthoritySnapshot]:
    case = _screened_case(m3_snapshot)
    screening = case.screening_results[0]
    pack = case.evidence_packs[0]
    monkeypatch.setattr(hearing_fixture, "RUN_ID", case.run_id)
    monkeypatch.setattr(hearing_fixture, "CASE_ID", case.case_id)
    monkeypatch.setattr(hearing_fixture, "MANIFEST_ID", case.manifest_id)
    monkeypatch.setattr(hearing_fixture, "INITIAL_PACK_ID", pack.pack_id)
    monkeypatch.setattr(hearing_fixture, "SCREENING_ID", screening.screening_id)
    monkeypatch.setattr(hearing_fixture, "VIOLATION", case.event.violation_type)
    disclosed_crop = pack.crops[0]
    fixture_ref = hearing_fixture._ref
    fixture_media_type = hearing_fixture.VLMMediaRef
    fixture_budget_type = hearing_fixture.VlmCallBudget
    fixture_usage_type = hearing_fixture.HearingUsageReceipt

    def exact_ref(kind: ArtifactKind, artifact_id: str) -> ArtifactRef:
        if kind == ArtifactKind.CROP and artifact_id.startswith("cycle-"):
            return ArtifactRef(
                kind=ArtifactKind.CROP,
                artifact_id=disclosed_crop.crop_id,
            )
        return fixture_ref(kind, artifact_id)

    def exact_media(**values: object) -> VLMMediaRef:
        if values.get("crop_id") == disclosed_crop.crop_id:
            return VLMMediaRef(
                crop_id=disclosed_crop.crop_id,
                media_sha256=disclosed_crop.media_sha256,
                local_path=disclosed_crop.local_path,
                source=disclosed_crop.source,
                media_access=disclosed_crop.privacy_receipt.media_access,
                privacy_policy=disclosed_crop.privacy_receipt.policy,
                privacy_transform_version=(disclosed_crop.privacy_receipt.transform_version),
                width=disclosed_crop.output_width,
                height=disclosed_crop.output_height,
            )
        return fixture_media_type(**values)

    def exact_budget(**values: object):
        if values.get("max_images") == 1:
            values["max_input_pixels"] = disclosed_crop.output_width * disclosed_crop.output_height
        return fixture_budget_type(**values)

    def exact_usage(**values: object):
        if values.get("input_images") == 1:
            values["input_pixels"] = disclosed_crop.output_width * disclosed_crop.output_height
        return fixture_usage_type(**values)

    monkeypatch.setattr(hearing_fixture, "_ref", exact_ref)
    monkeypatch.setattr(hearing_fixture, "VLMMediaRef", exact_media)
    monkeypatch.setattr(hearing_fixture, "VlmCallBudget", exact_budget)
    monkeypatch.setattr(hearing_fixture, "HearingUsageReceipt", exact_usage)

    session = hearing_fixture._session()
    checkpoint = begin_hearing(session)
    retrieval = hearing_fixture._retrieval(session, checkpoint)
    checkpoint = complete_precedent_retrieval(session, checkpoint, retrieval)
    payloads = hearing_fixture._payloads(
        evidence_ref=hearing_fixture._ref(
            hearing_fixture.ArtifactKind.CROP,
            "cycle-1-visible-crop",
        )
    )
    prosecutor, prosecutor_trace = hearing_fixture._role_output(
        session, checkpoint, retrieval, payloads[0]
    )
    if repair_prosecutor:
        prosecutor_trace = hearing_fixture._repair_trace(
            prosecutor_trace.calls[0],
            payloads[0],
        )
        repaired_call = prosecutor_trace.calls[-1]
        prosecutor_payload = prosecutor.model_dump(mode="python", exclude_computed_fields=True)
        prosecutor_payload.update(
            {
                "request_ref": repaired_call.request_ref,
                "response_ref": repaired_call.response_ref,
                "parse_receipt_ref": repaired_call.parse_receipt_ref,
            }
        )
        prosecutor = HearingRoleOutput.model_validate(prosecutor_payload)
    checkpoint = complete_prosecutor(session, checkpoint, prosecutor, prosecutor_trace)
    defender, defender_trace = hearing_fixture._role_output(
        session,
        checkpoint,
        retrieval,
        payloads[1],
        prosecutor_output_id=prosecutor.output_id,
    )
    checkpoint = complete_defender(session, checkpoint, defender, defender_trace)
    judge, judge_trace = hearing_fixture._role_output(
        session,
        checkpoint,
        retrieval,
        payloads[2],
        prosecutor_output_id=prosecutor.output_id,
        defender_output_id=defender.output_id,
    )
    checkpoint = complete_judge(session, checkpoint, judge, judge_trace).checkpoint
    hearing_round = HearingRound(
        run_id=case.run_id,
        case_id=case.case_id,
        hearing_session_id=session.session_id,
        round_index=1,
        prior_acquisition_rounds=0,
        prior_rework_rounds=0,
        current_evidence_pack_id=pack.pack_id,
        current_evidence_pack_version=pack.version,
        precedent_retrieval_degraded=True,
        precedent_retrieval_receipt=retrieval,
        prosecutor_output=prosecutor,
        defender_output=defender,
        judge_output=judge,
        manifest_id=case.manifest_id,
    )
    record = hearing_fixture._record(
        session,
        (hearing_round,),
        (checkpoint,),
    )
    verdict, binding = build_hearing_verdict(record, case.event.violation_type)
    case = Case.model_validate(
        {
            **case.model_dump(mode="json", exclude_computed_fields=True),
            "status": CaseStatus.PROCEDURAL_REVIEW.value,
            "verdicts": (verdict.model_dump(mode="json"),),
        }
    )
    traces = (prosecutor_trace, defender_trace, judge_trace)
    documents = [
        _m4_document(M4ProjectionArtifactKind.VERDICT, verdict.verdict_id, verdict),
        _m4_document(
            M4ProjectionArtifactKind.VERDICT_BINDING,
            binding.binding_id,
            binding,
        ),
        _m4_document(M4ProjectionArtifactKind.HEARING_RECORD, record.record_id, record),
        _m4_document(
            M4ProjectionArtifactKind.HEARING_ROUND,
            hearing_round.round_id,
            hearing_round,
        ),
    ]
    for output, trace in zip((prosecutor, defender, judge), traces, strict=True):
        documents.append(
            _m4_document(
                M4ProjectionArtifactKind.ROLE_OUTPUT,
                output.output_id,
                output,
            )
        )
        documents.extend(
            _m4_document(
                M4ProjectionArtifactKind.MODEL_REQUEST,
                call.request.request_id,
                call.request,
            )
            for call in trace.calls
        )
    snapshot = M6ValidatedM4ReplayAuthoritySnapshot(
        source_identity_sha256=m3_snapshot.source_identity_sha256,
        run_id=case.run_id,
        documents=tuple(sorted(documents, key=lambda item: item.sort_key)),
    )
    return case, snapshot


def test_screening_repair_uses_original_request_disclosure_scope() -> None:
    snapshot = _repair_snapshot()
    case = _screened_case(snapshot)

    bindings = resolve_m6_screening_model_reference_bindings(
        source_case=case,
        snapshot=snapshot,
    )

    final_request = next(
        item.request
        for item in snapshot.requests
        if isinstance(item.request, StructureRepairRequest)
    )
    original = next(
        item.request for item in snapshot.requests if isinstance(item.request, VLMRequest)
    )
    assert bindings[0].final_request_id == final_request.request_id
    assert bindings[0].scope.request_id == original.request_id
    assert bindings[0].scope.evidence_pack_id == original.evidence_pack_id
    assert bindings[0].scope.evidence_pack_version == original.evidence_pack_version
    assert bindings[0].scope.cycle_scope_id is None
    assert bindings[0].scope.allowed_evidence_refs == original.allowed_evidence_refs


def test_screening_scope_rejects_foreign_or_future_authority_ref() -> None:
    snapshot = _repair_snapshot(foreign_scope_ref=True)
    case = _screened_case(snapshot)

    with pytest.raises(M6ModelReferenceAuthorityError) as raised:
        resolve_m6_screening_model_reference_bindings(
            source_case=case,
            snapshot=snapshot,
        )

    assert raised.value.code == M6ModelReferenceAuthorityErrorCode.M3_SCOPE_CLOSURE_MISMATCH


def test_fast_verdict_binding_uses_exact_screening_history_and_no_m4_authority() -> None:
    m3_snapshot = _repair_snapshot()
    case = _fast_case(m3_snapshot)
    screening_bindings = resolve_m6_screening_model_reference_bindings(
        source_case=case,
        snapshot=m3_snapshot,
    )

    fast_bindings = resolve_m6_fast_verdict_model_reference_bindings(
        source_case=case,
        screening_bindings=screening_bindings,
    )
    authority = assemble_m6_case_model_reference_authority(
        source_case=case,
        m3_snapshot=m3_snapshot,
        m4_snapshot=M6ValidatedM4ReplayAuthoritySnapshot(
            source_identity_sha256=m3_snapshot.source_identity_sha256,
            run_id=case.run_id,
            documents=(),
        ),
    )

    assert len(fast_bindings) == 1
    assert isinstance(fast_bindings[0], M6FastVerdictModelReferenceBinding)
    assert fast_bindings[0].scope == screening_bindings[0].scope
    assert fast_bindings[0].response_ids == tuple(
        sorted(ref.artifact_id for ref in case.verdicts[0].model_response_refs)
    )
    assert authority.fast_verdict_bindings == fast_bindings
    assert authority.verdict_bindings == ()


def test_fast_verdict_binding_rejects_a_case_authored_verdict_mutation() -> None:
    m3_snapshot = _repair_snapshot()
    case = _fast_case(m3_snapshot)
    verdict_payload = case.verdicts[0].model_dump(
        mode="json",
        exclude_computed_fields=True,
    )
    verdict_payload["rationale_summary"] = "mutated after the sealed M3 parse"
    mutated = Case.model_validate(
        {
            **case.model_dump(mode="json", exclude_computed_fields=True),
            "verdicts": (verdict_payload,),
        }
    )
    screening_bindings = resolve_m6_screening_model_reference_bindings(
        source_case=mutated,
        snapshot=m3_snapshot,
    )

    with pytest.raises(M6ModelReferenceAuthorityError) as raised:
        resolve_m6_fast_verdict_model_reference_bindings(
            source_case=mutated,
            screening_bindings=screening_bindings,
        )

    assert raised.value.code == (M6ModelReferenceAuthorityErrorCode.M3_FAST_VERDICT_CLOSURE_INVALID)


def test_hearing_binding_resolves_exact_three_role_scopes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    m3_snapshot = _repair_snapshot()
    case, m4_snapshot = _m4_case_and_snapshot(m3_snapshot, monkeypatch)

    authority = assemble_m6_case_model_reference_authority(
        source_case=case,
        m3_snapshot=m3_snapshot,
        m4_snapshot=m4_snapshot,
    )

    assert len(authority.screening_bindings) == 1
    assert len(authority.verdict_bindings) == 1
    roles = authority.verdict_bindings[0].role_bindings
    assert tuple(item.role for item in roles) == (
        VlmRole.PROSECUTOR,
        VlmRole.DEFENDER,
        VlmRole.JUDGE,
    )
    assert all(item.scope.allowed_evidence_refs for item in roles)
    assert all(item.final_request_id == item.scope.request_id for item in roles)
    assert all(item.scope.evidence_pack_id == case.verdicts[0].evidence_pack_id for item in roles)
    assert all(item.scope.cycle_scope_id is not None for item in roles)


def test_hearing_repair_keeps_final_request_but_uses_primary_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    m3_snapshot = _repair_snapshot()
    case, snapshot = _m4_case_and_snapshot(
        m3_snapshot,
        monkeypatch,
        repair_prosecutor=True,
    )

    bindings = resolve_m6_hearing_model_reference_bindings(
        source_case=case,
        snapshot=snapshot,
    )

    prosecutor = bindings[0].role_bindings[0]
    assert prosecutor.role == VlmRole.PROSECUTOR
    assert prosecutor.final_request_id != prosecutor.scope.request_id
    assert prosecutor.scope.cycle_scope_id is not None


def test_hearing_binding_fails_closed_when_one_role_request_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    m3_snapshot = _repair_snapshot()
    case, snapshot = _m4_case_and_snapshot(m3_snapshot, monkeypatch)
    request_documents = tuple(
        item for item in snapshot.documents if item.kind == M4ProjectionArtifactKind.MODEL_REQUEST
    )
    damaged = replace(
        snapshot,
        documents=tuple(item for item in snapshot.documents if item != request_documents[0]),
    )

    with pytest.raises(M6ModelReferenceAuthorityError) as raised:
        resolve_m6_hearing_model_reference_bindings(
            source_case=case,
            snapshot=damaged,
        )

    assert raised.value.code == M6ModelReferenceAuthorityErrorCode.M4_ROLE_REQUEST_MISSING


def test_hearing_scope_rejects_foreign_or_future_evidence_ref(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    m3_snapshot = _repair_snapshot()
    case, snapshot = _m4_case_and_snapshot(m3_snapshot, monkeypatch)
    request_document = next(
        item for item in snapshot.documents if item.kind == M4ProjectionArtifactKind.MODEL_REQUEST
    )
    round_document = next(
        item for item in snapshot.documents if item.kind == M4ProjectionArtifactKind.HEARING_ROUND
    )
    request = HearingModelRequest.model_validate_json(request_document.canonical_document)
    hearing_round = HearingRound.model_validate_json(round_document.canonical_document)
    pack = next(
        item
        for item in case.evidence_packs
        if (item.pack_id, item.version)
        == (request.current_evidence_pack_id, request.current_evidence_pack_version)
    )
    foreign = ArtifactRef(
        kind=ArtifactKind.OBJECTIVE_FACT,
        artifact_id="future-hearing-fact",
    )
    payload = request.model_dump(mode="json", exclude_computed_fields=True)
    payload["allowed_evidence_refs"] = [
        ref.model_dump(mode="json")
        for ref in sorted(
            (*request.allowed_evidence_refs, foreign),
            key=lambda ref: ref.sort_key,
        )
    ]
    forged = HearingModelRequest.model_validate(payload)

    with pytest.raises(M6ModelReferenceAuthorityError) as raised:
        m6_model_reference_authority._require_m4_scope_closure(
            pack,
            forged,
            hearing_round,
        )

    assert raised.value.code == M6ModelReferenceAuthorityErrorCode.M4_SCOPE_CLOSURE_MISMATCH


def test_combined_authority_rejects_cross_snapshot_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    m3_snapshot = _repair_snapshot()
    case, m4_snapshot = _m4_case_and_snapshot(m3_snapshot, monkeypatch)
    foreign = replace(
        m4_snapshot,
        source_identity_sha256=hashlib.sha256(b"foreign").hexdigest(),
    )

    with pytest.raises(M6ModelReferenceAuthorityError) as raised:
        assemble_m6_case_model_reference_authority(
            source_case=case,
            m3_snapshot=m3_snapshot,
            m4_snapshot=foreign,
        )

    assert raised.value.code == M6ModelReferenceAuthorityErrorCode.SNAPSHOT_IDENTITY_MISMATCH
