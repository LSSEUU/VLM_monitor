from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from typing import TypeVar

import pytest
from pydantic import BaseModel

import tests.unit.test_m4_hearing_procedural_review as m4_fixture
from labcourt.application.hearing_history import derive_hearing_evidence_grant
from labcourt.application.m6_procedural_gate_authority import (
    M6ProceduralGateAuthorityError,
    M6ProceduralGateAuthorityErrorCode,
    assemble_m6_case_procedural_gate_authority,
)
from labcourt.application.m6_source_authority import M6ValidatedSourceAuthority
from labcourt.contracts.artifact_validation import (
    ArtifactValidationReport,
    M3ArtifactValidationReport,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case
from labcourt.contracts.enums import (
    ArtifactKind,
    CaseStatus,
    MediaAvailability,
    ProceduralDefectCode,
    UnknownReferenceNamespace,
    VerificationStatus,
    VlmRole,
)
from labcourt.contracts.evidence import Crop
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.hearing import (
    HearingModelParseReceipt,
    HearingModelRequest,
    HearingRecord,
    HearingRound,
    HearingUnknownReferenceAttempt,
    HearingUnknownReferenceSource,
    JudgeFinalDecisionPayload,
    JudgeModelPayload,
)
from labcourt.contracts.m3_models import EvidenceCitation
from labcourt.contracts.m4_artifact_validation import M4ArtifactValidationReport
from labcourt.contracts.m4_projection import M4ProjectionArtifactKind
from labcourt.contracts.m5_artifact_validation import M5ArtifactValidationReport
from labcourt.contracts.m6_source_authority import (
    M6GateCurrentClosureBasis,
    M6GateCurrentClosureReceipt,
    M6ReplayInputAuthority,
)
from labcourt.contracts.storage import ArtifactRef, ArtifactVerification
from labcourt.domain.hearing_fsm import HearingCallClosure
from labcourt.domain.hearing_verdict_builder import build_hearing_verdict
from labcourt.domain.m6_procedural_gate_authority import (
    M6ProceduralGateExecutionInput,
)
from labcourt.domain.procedural_gate import (
    ArtifactBounds,
    ProceduralGateAuthorityError,
    ProceduralGateInput,
    review_verdict,
)
from labcourt.ports.m6_historical_retrieval import M6HistoricalAuthorityDocument
from labcourt.ports.m6_procedural_gate_authority import (
    M6ProceduralGateHistorySnapshot,
)
from tests.contract.test_m3_contracts import _parsed, _screening

_ModelT = TypeVar("_ModelT", bound=BaseModel)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _document_sha256(value: BaseModel) -> str:
    return _sha(canonical_json(value.model_dump(mode="json")))


def _updated(value: _ModelT, **updates: object) -> _ModelT:
    payload = value.model_dump(mode="json", exclude_computed_fields=True)
    payload.update(updates)
    return type(value).model_validate(payload)


def _verification(crop: Crop) -> ArtifactVerification:
    return ArtifactVerification(
        artifact_ref=ArtifactRef(
            kind=ArtifactKind.CROP,
            artifact_id=crop.crop_id,
        ),
        status=VerificationStatus.CURRENT_MEDIA_VERIFIED,
        availability=MediaAvailability.AVAILABLE,
        media_type=crop.media_type,
        expected_source_pixel_sha256=crop.source_media_sha256,
        expected_output_pixel_sha256=crop.pixel_sha256,
        actual_output_pixel_sha256=crop.pixel_sha256,
        expected_media_sha256=crop.media_sha256,
        actual_media_sha256=crop.media_sha256,
        expected_width=crop.output_width,
        actual_width=crop.output_width,
        expected_height=crop.output_height,
        actual_height=crop.output_height,
        expected_size_bytes=crop.size_bytes,
        actual_size_bytes=crop.size_bytes,
    )


def _record_with_history(
    record: HearingRecord,
    hearing_round: HearingRound,
    history: tuple[HearingCallClosure, ...],
) -> HearingRecord:
    return _updated(
        record,
        rounds=(hearing_round,),
        model_request_refs=tuple(
            sorted((call.request_ref for call in history), key=lambda item: item.sort_key)
        ),
        model_response_refs=tuple(
            sorted((call.response_ref for call in history), key=lambda item: item.sort_key)
        ),
        parse_receipt_refs=tuple(
            sorted((call.parse_receipt_ref for call in history), key=lambda item: item.sort_key)
        ),
        usage_receipts=tuple(
            sorted(
                (call.usage for call in history),
                key=lambda item: (
                    item.round_index,
                    item.role.value,
                    item.request_ref.artifact_id,
                ),
            )
        ),
    )


def _parse_only_attempt(
    record: HearingRecord,
    history: tuple[HearingCallClosure, ...],
) -> tuple[HearingRecord, tuple[HearingCallClosure, ...]]:
    first = history[-1]
    attempt = HearingUnknownReferenceAttempt(
        namespace=UnknownReferenceNamespace.EVIDENCE,
        source=HearingUnknownReferenceSource.JUDGE_CITATION_REF,
        value_sha256=_sha("parse-only-unknown-reference"),
    )
    receipt = _updated(
        first.parse_receipt,
        unknown_reference_attempts=(attempt,),
    )
    assert isinstance(receipt, HearingModelParseReceipt)
    replacement = HearingCallClosure(
        request=first.request,
        response=first.response,
        parse_receipt=receipt,
        usage=first.usage,
    )
    hearing_round = record.rounds[0]
    judge = _updated(
        hearing_round.judge_output,
        parse_receipt_ref=replacement.parse_receipt_ref,
    )
    hearing_round = _updated(hearing_round, judge_output=judge)
    revised_history = (*history[:-1], replacement)
    return _record_with_history(record, hearing_round, revised_history), revised_history


def _replace_judge(
    record: HearingRecord,
    history: tuple[HearingCallClosure, ...],
    *,
    invalid_coordinate: bool = False,
) -> tuple[HearingRecord, tuple[HearingCallClosure, ...]]:
    old = history[-1]
    old_output = record.rounds[0].judge_output
    assert isinstance(old_output.payload, JudgeModelPayload)
    payload = old_output.payload
    request = old.request
    if invalid_coordinate:
        outcome = payload.outcome
        assert isinstance(outcome, JudgeFinalDecisionPayload)
        crop = request.media[0]
        citation = EvidenceCitation(
            evidence_ref=ArtifactRef(kind=ArtifactKind.CROP, artifact_id=crop.crop_id),
            bbox=BBoxXYXY(x1=0, y1=0, x2=crop.width + 1, y2=10),
            coordinate_space="CITED_ARTIFACT_PIXELS",
        )
        outcome = _updated(outcome, evidence_citations=(citation,))
        payload = _updated(payload, outcome=outcome)
    replacement, judge_output = m4_fixture._call(request, payload)
    hearing_round = _updated(record.rounds[0], judge_output=judge_output)
    revised_history = (*history[:-1], replacement)
    return _record_with_history(record, hearing_round, revised_history), revised_history


@dataclass(frozen=True)
class _Bundle:
    source: M6ValidatedSourceAuthority
    snapshot: M6ProceduralGateHistorySnapshot
    config: object
    record: HearingRecord
    history: tuple[HearingCallClosure, ...]


def _m4_document(
    kind: M4ProjectionArtifactKind,
    artifact_id: str,
    value: BaseModel,
) -> M6HistoricalAuthorityDocument:
    return M6HistoricalAuthorityDocument(
        kind=kind,
        artifact_id=artifact_id,
        canonical_document=canonical_json(value.model_dump(mode="json")),
    )


def _bundle(
    monkeypatch: pytest.MonkeyPatch,
    *,
    mode: str = "clean",
) -> _Bundle:
    crop_count = 1
    if mode == "cross-role":
        crop_count = 2
    seed_pack = m4_fixture._pack(crop_count)
    parsed = _parsed(
        run_id=seed_pack.run_id,
        case_id=seed_pack.case_id,
        evidence_pack_id=seed_pack.pack_id,
        evidence_pack_version=seed_pack.version,
        violation_type=seed_pack.event.violation_type,
        evidence_class=seed_pack.event.evidence_class,
        probability=0.5,
        manifest_id=seed_pack.manifest_id,
    )
    screening = _screening(
        parsed,
        l1_score=seed_pack.event.l1_score,
    )
    monkeypatch.setattr(m4_fixture, "SCREENING_ID", screening.screening_id)
    if mode == "bounds-forgery":
        original_request = m4_fixture._request

        def forged_request(**values: object) -> HearingModelRequest:
            request = original_request(**values)  # type: ignore[arg-type]
            media = tuple(_updated(item, width=item.width + 1) for item in request.media)
            budget = _updated(
                request.budget,
                max_input_pixels=sum(item.width * item.height for item in media),
            )
            return _updated(request, media=media, budget=budget)

        monkeypatch.setattr(m4_fixture, "_request", forged_request)
    rig = (
        m4_fixture._rig(
            crop_count=2,
            disclosed_crop_by_role={
                VlmRole.PROSECUTOR: 0,
                VlmRole.DEFENDER: 0,
                VlmRole.JUDGE: 1,
            },
            prosecutor_citation_index=1,
        )
        if mode == "cross-role"
        else m4_fixture._rig()
    )
    assert rig.pack == seed_pack
    record = rig.record
    history = rig.call_history
    if mode == "parse-only":
        record, history = _parse_only_attempt(record, history)
    elif mode == "coordinate":
        record, history = _replace_judge(record, history, invalid_coordinate=True)
    grant = derive_hearing_evidence_grant(record, history)
    verdict, binding = build_hearing_verdict(record, rig.pack.event.violation_type)
    review = (
        review_verdict(
            ProceduralGateInput(
                verdict=verdict,
                evidence_pack=rig.pack,
                current_closure=rig.closure,
                gate_config=rig.config.procedural_gate,
                alert_config=rig.config.alerts,
                gate_version=rig.config.procedural_gate.gate_version,
                review_version=1,
            )
        )
        if mode == "bounds-forgery"
        else rig.verifier.rebuild_review(
            record=record,
            verdict=verdict,
            binding=binding,
            evidence_pack=rig.pack,
            current_closure=rig.closure,
            call_history=history,
            evidence_grant=grant,
            review_version=1,
        )
    )
    status = CaseStatus.READY_FOR_ALERT_POLICY if review.passed else CaseStatus.REWORK_REQUIRED
    case = Case(
        run_id=rig.pack.run_id,
        status=status,
        event=rig.pack.event,
        evidence_packs=(rig.pack,),
        screening_results=(screening,),
        verdicts=(verdict,),
        procedural_reviews=(review,),
        manifest_id=rig.pack.manifest_id,
    )
    m4_root = _sha("full-m4-gate-root")
    m5_root = _sha("full-m5-root")
    m2_report = ArtifactValidationReport(
        run_id=case.run_id,
        manifest_id=case.manifest_id,
        audit_head_sequence=0,
        audit_head_hash=_sha("audit-head"),
    )
    m3_report = M3ArtifactValidationReport(run_id=case.run_id, m2_report=m2_report)
    m4_report = M4ArtifactValidationReport(
        run_id=case.run_id,
        m3_report=m3_report,
        authority_root_sha256=m4_root,
    )
    report = M5ArtifactValidationReport(
        run_id=case.run_id,
        manifest_id=case.manifest_id,
        config_sha256=rig.config.config_sha256,
        predecessor_report=m4_report,
        authority_root_sha256=m5_root,
    )
    case_document = canonical_json(case.model_dump(mode="json"))
    manifest_document = canonical_json(rig.manifest.model_dump(mode="json"))
    report_document = canonical_json(report.model_dump(mode="json"))
    closure_receipt = M6GateCurrentClosureReceipt(
        run_id=case.run_id,
        case_id=case.case_id,
        manifest_id=case.manifest_id,
        review_version=review.version,
        source_review_id=review.review_id,
        source_review_document_sha256=_document_sha256(review),
        evidence_pack_id=rig.pack.pack_id,
        evidence_pack_version=rig.pack.version,
        evidence_pack_document_sha256=_document_sha256(rig.pack),
        basis=M6GateCurrentClosureBasis.CURRENT_PRIVACY_CROP_REVERIFIED,
        current_closure=rig.closure,
        crop_verifications=tuple(
            sorted(
                (_verification(crop) for crop in rig.pack.crops),
                key=lambda item: item.artifact_ref.sort_key,
            )
        ),
    )
    input_authority = M6ReplayInputAuthority(
        sample_id="sample-gate-history",
        source_run_id=case.run_id,
        source_case_id=case.case_id,
        source_case_revision=1,
        source_case_document_sha256=_sha(case_document),
        source_manifest_id=case.manifest_id,
        source_manifest_document_sha256=_sha(manifest_document),
        source_config_sha256=rig.config.config_sha256,
        source_m4_authority_root_sha256=m4_root,
        source_m5_authority_root_sha256=m5_root,
        source_validation_report_id=report.report_id,
        source_validation_report_document_sha256=_sha(report_document),
        frame_inventory_root_sha256=_sha("frames"),
        detection_inventory_root_sha256=_sha("detections"),
        model_call_inventory_root_sha256=_sha("model-calls"),
        embedding_inventory_root_sha256=_sha("embeddings"),
        tool_result_inventory_root_sha256=_sha("tools"),
        historical_causal_cut_id=_sha("historical-cut"),
        gate_current_closures=(closure_receipt,),
    )
    source = M6ValidatedSourceAuthority(
        source_identity_sha256=_sha("immutable-source"),
        input_authority=input_authority,
        source_validation_report=report,
        source_case=case,
        source_manifest=rig.manifest,
    )
    documents = [
        _m4_document(M4ProjectionArtifactKind.EVIDENCE_PACK, rig.pack.pack_id, rig.pack),
        _m4_document(M4ProjectionArtifactKind.VERDICT, verdict.verdict_id, verdict),
        _m4_document(
            M4ProjectionArtifactKind.PROCEDURAL_REVIEW,
            review.review_id,
            review,
        ),
        _m4_document(
            M4ProjectionArtifactKind.VERDICT_BINDING,
            binding.binding_id,
            binding,
        ),
        _m4_document(M4ProjectionArtifactKind.HEARING_RECORD, record.record_id, record),
    ]
    for hearing_round in record.rounds:
        documents.append(
            _m4_document(
                M4ProjectionArtifactKind.HEARING_ROUND,
                hearing_round.round_id,
                hearing_round,
            )
        )
        receipt = hearing_round.precedent_retrieval_receipt
        documents.append(
            _m4_document(
                M4ProjectionArtifactKind.PRECEDENT_RETRIEVAL,
                receipt.receipt_id,
                receipt,
            )
        )
        for output in (
            hearing_round.prosecutor_output,
            hearing_round.defender_output,
            hearing_round.judge_output,
        ):
            documents.append(
                _m4_document(M4ProjectionArtifactKind.ROLE_OUTPUT, output.output_id, output)
            )
    for call in history:
        documents.extend(
            (
                _m4_document(
                    M4ProjectionArtifactKind.MODEL_REQUEST,
                    call.request.request_id,
                    call.request,
                ),
                _m4_document(
                    M4ProjectionArtifactKind.MODEL_RESPONSE,
                    call.response.response_id,
                    call.response,
                ),
                _m4_document(
                    M4ProjectionArtifactKind.MODEL_PARSE_RECEIPT,
                    call.parse_receipt.parse_receipt_id,
                    call.parse_receipt,
                ),
                _m4_document(
                    M4ProjectionArtifactKind.USAGE_RECEIPT,
                    call.usage.usage_receipt_id,
                    call.usage,
                ),
            )
        )
    snapshot = M6ProceduralGateHistorySnapshot(
        source_identity_sha256=source.source_identity_sha256,
        run_id=case.run_id,
        source_m4_authority_root_sha256=m4_root,
        documents=tuple(sorted(documents, key=lambda item: item.sort_key)),
    )
    return _Bundle(
        source=source,
        snapshot=snapshot,
        config=rig.config,
        record=record,
        history=history,
    )


def _assemble(bundle: _Bundle):
    return assemble_m6_case_procedural_gate_authority(
        source=bundle.source,
        snapshot=bundle.snapshot,
        config=bundle.config,  # type: ignore[arg-type]
    )


def _assert_error(code: M6ProceduralGateAuthorityErrorCode, bundle: _Bundle) -> None:
    with pytest.raises(M6ProceduralGateAuthorityError) as raised:
        _assemble(bundle)
    assert raised.value.code == code


def test_derives_exact_gate_input_and_matches_independent_m4_verifier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _bundle(monkeypatch)

    authority = _assemble(bundle)

    source_review = bundle.source.source_case.procedural_reviews[0]
    execution = authority.input_for_review(source_review)
    assert execution.rebuild_review() == source_review
    assert execution.unknown_reference_attempts == ()
    assert (
        execution.artifact_bounds
        == derive_hearing_evidence_grant(
            bundle.record,
            bundle.history,
        ).artifact_bounds
    )


def test_parse_receipt_only_unknown_reference_cannot_be_omitted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = _assemble(_bundle(monkeypatch, mode="parse-only"))
    execution = authority.inputs[0]

    assert len(execution.unknown_reference_attempts) == 1
    assert ProceduralDefectCode.FABRICATED_EVIDENCE_REFERENCE in {
        item.code for item in execution.rebuild_review().defects
    }


def test_cross_role_reference_is_derived_even_when_crop_exists_in_pack(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = _assemble(_bundle(monkeypatch, mode="cross-role"))
    execution = authority.inputs[0]

    assert len(execution.unknown_reference_attempts) == 1
    assert execution.rebuild_review().passed is False


def test_exact_media_bounds_prevent_caller_from_erasing_coordinate_defect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = _assemble(_bundle(monkeypatch, mode="coordinate"))
    exact = authority.inputs[0]
    exact_review = exact.rebuild_review()
    assert ProceduralDefectCode.INVALID_COORDINATES in {item.code for item in exact_review.defects}
    bound = exact.artifact_bounds[0]
    with pytest.raises(ProceduralGateAuthorityError, match="conflict"):
        M6ProceduralGateExecutionInput(
            source_review_id=exact.source_review_id,
            source_review_document_sha256=exact.source_review_document_sha256,
            verdict=exact.verdict,
            evidence_pack=exact.evidence_pack,
            current_closure=exact.current_closure,
            gate_config=exact.gate_config,
            alert_config=exact.alert_config,
            review_version=exact.review_version,
            unknown_reference_attempts=exact.unknown_reference_attempts,
            precedent_resolutions=exact.precedent_resolutions,
            artifact_bounds=(
                ArtifactBounds(
                    artifact_ref=bound.artifact_ref,
                    width=bound.width + 1,
                    height=bound.height,
                ),
            ),
        )
    assert exact_review.passed is False


def test_self_consistent_forged_request_bounds_are_rejected_by_crop_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _bundle(monkeypatch, mode="bounds-forgery")
    assert bundle.source.source_case.procedural_reviews[0].passed is True

    _assert_error(
        M6ProceduralGateAuthorityErrorCode.MEDIA_AUTHORITY_MISMATCH,
        bundle,
    )


@pytest.mark.parametrize(
    "kind",
    (
        M4ProjectionArtifactKind.VERDICT_BINDING,
        M4ProjectionArtifactKind.USAGE_RECEIPT,
    ),
)
def test_missing_binding_or_usage_document_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    kind: M4ProjectionArtifactKind,
) -> None:
    bundle = _bundle(monkeypatch)
    damaged = replace(
        bundle.snapshot,
        documents=tuple(item for item in bundle.snapshot.documents if item.kind != kind),
    )

    _assert_error(
        M6ProceduralGateAuthorityErrorCode.M4_DOCUMENT_MISSING,
        replace(bundle, snapshot=damaged),
    )


def test_requires_same_snapshot_identity_and_exact_m4_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _bundle(monkeypatch)
    _assert_error(
        M6ProceduralGateAuthorityErrorCode.SNAPSHOT_IDENTITY_MISMATCH,
        replace(
            bundle,
            snapshot=replace(
                bundle.snapshot,
                source_identity_sha256=_sha("foreign-snapshot"),
            ),
        ),
    )
    _assert_error(
        M6ProceduralGateAuthorityErrorCode.SOURCE_AUTHORITY_ROOT_MISMATCH,
        replace(
            bundle,
            snapshot=replace(
                bundle.snapshot,
                source_m4_authority_root_sha256=_sha("foreign-root"),
            ),
        ),
    )
