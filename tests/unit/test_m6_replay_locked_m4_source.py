from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

import tests.unit.test_m6_model_reference_authority as model_reference_fixture
from labcourt.application.m6_model_call_authority import (
    assemble_m6_locked_screening_model_calls,
)
from labcourt.application.m6_model_reference_authority import (
    assemble_m6_case_model_reference_authority,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.cases import Case
from labcourt.contracts.config import AppConfig
from labcourt.contracts.enums import CaseStatus, VlmRole
from labcourt.contracts.hearing_state import HearingRecord, HearingVerdictBinding
from labcourt.contracts.m4_projection import M4ProjectionArtifactKind
from labcourt.contracts.m6_replay_locked import (
    M6HistoricalCausalCut,
    M6LockedDetectionInput,
    M6LockedEmbeddingChannel,
    M6LockedEmbeddingInput,
    M6LockedEmbeddingScope,
    M6LockedFrameInput,
    M6LockedModelCallInput,
    M6LockedModelCallLayer,
    M6LockedModelCallResultKind,
    M6LockedModelRole,
    M6LockedRetrievalCycleInput,
    M6LockedRetrievalOutcomeKind,
    M6ReplayAuthorityKind,
    M6ReplayAuthorityRef,
    M6ReplayInputClosureAuthority,
)
from labcourt.contracts.m6_source_authority import (
    M6GateCurrentClosureBasis,
    M6GateCurrentClosureReceipt,
)
from labcourt.domain.m6_procedural_gate_authority import (
    M6CaseProceduralGateAuthority,
    M6ProceduralGateExecutionInput,
)
from labcourt.domain.m6_semantic_projection import (
    M6ResolvedRetrievalCycle,
    M6VerifiedProjectionContext,
    build_m6_case_replay_snapshot,
    resolve_m6_locked_model_responses,
)
from labcourt.ports.m6_replay_locked_m4_source import (
    M6ReplayLockedM4GateTerminalSource,
)
from tests.integration.test_m3_sqlite_repository import (
    _parsed,
    _parsed_receipt,
    _screening_for,
)
from tests.unit.test_m6_model_call_authority import _response_snapshot
from tests.unit.test_m6_model_reference_authority import _m4_case_and_snapshot
from tests.unit.test_m6_semantic_projection import (
    _current_closure,
    _resolved_perception,
)
from tests.unit.test_m6_source_authority import _bundle, _verification


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _document_sha256(value: object) -> str:
    assert hasattr(value, "model_dump")
    document = canonical_json(value.model_dump(mode="json"))  # type: ignore[attr-defined]
    return _sha(document)


def _authority_ref(
    kind: M6ReplayAuthorityKind,
    artifact_id: str,
    label: str,
) -> M6ReplayAuthorityRef:
    return M6ReplayAuthorityRef(
        kind=kind,
        artifact_id=artifact_id,
        document_sha256=_sha(label),
    )


def _hearing_calls(record: HearingRecord) -> tuple[M6LockedModelCallInput, ...]:
    hearing_round = record.rounds[0]
    outputs = (
        hearing_round.prosecutor_output,
        hearing_round.defender_output,
        hearing_round.judge_output,
    )
    role_by_vlm = {
        VlmRole.PROSECUTOR: M6LockedModelRole.PROSECUTOR,
        VlmRole.DEFENDER: M6LockedModelRole.DEFENDER,
        VlmRole.JUDGE: M6LockedModelRole.JUDGE,
    }
    return tuple(
        M6LockedModelCallInput(
            layer=M6LockedModelCallLayer.HEARING,
            role=role_by_vlm[output.role],
            attempt_index=0,
            request_ref=_authority_ref(
                M6ReplayAuthorityKind.M4_MODEL_REQUEST,
                output.request_ref.artifact_id,
                f"request:{output.request_ref.artifact_id}",
            ),
            result_kind=M6LockedModelCallResultKind.RESPONSE,
            response_ref=_authority_ref(
                M6ReplayAuthorityKind.M4_MODEL_RESPONSE,
                output.response_ref.artifact_id,
                f"response:{output.response_ref.artifact_id}",
            ),
            cache_ref=_authority_ref(
                M6ReplayAuthorityKind.M4_MODEL_CACHE,
                _sha(f"cache:{output.request_ref.artifact_id}"),
                f"cache-document:{output.request_ref.artifact_id}",
            ),
            parse_receipt_ref=_authority_ref(
                M6ReplayAuthorityKind.M4_PARSE_RECEIPT,
                output.parse_receipt_ref.artifact_id,
                f"parse:{output.parse_receipt_ref.artifact_id}",
            ),
            parsed_output_ref=_authority_ref(
                M6ReplayAuthorityKind.M4_ROLE_OUTPUT,
                output.output_id,
                f"output:{output.output_id}",
            ),
            raw_content_sha256=_sha(f"content:{output.response_ref.artifact_id}"),
            raw_size_bytes=128,
        )
        for output in outputs
    )


def _terminal_source(
    monkeypatch: pytest.MonkeyPatch,
) -> M6ReplayLockedM4GateTerminalSource:
    _, m3_snapshot = _response_snapshot()
    source_case = model_reference_fixture._screened_case(m3_snapshot)
    request = m3_snapshot.requests[0].request
    response = m3_snapshot.responses[0].response
    parsed = _parsed(request, response, violation_probability=0.5)
    parse_receipt = _parsed_receipt(request, response, parsed)
    m3_snapshot = replace(
        m3_snapshot,
        parse_receipts=(
            replace(
                m3_snapshot.parse_receipts[0],
                receipt=parse_receipt,
                document_sha256=_document_sha256(parse_receipt),
            ),
        ),
        parsed_outputs=(
            replace(
                m3_snapshot.parsed_outputs[0],
                output=parsed,
                document_sha256=_document_sha256(parsed),
            ),
        ),
    )
    screening = _screening_for(source_case.evidence_packs[0], parsed)
    escalated_case = Case.model_validate(
        {
            **source_case.model_dump(mode="json", exclude_computed_fields=True),
            "status": CaseStatus.ESCALATED.value,
            "screening_results": (screening.model_dump(mode="json"),),
        }
    )
    monkeypatch.setattr(
        model_reference_fixture,
        "_screened_case",
        lambda _snapshot: escalated_case,
    )
    pending_case, m4_snapshot = _m4_case_and_snapshot(m3_snapshot, monkeypatch)
    record_document = next(
        item
        for item in m4_snapshot.documents
        if item.kind == M4ProjectionArtifactKind.HEARING_RECORD
    )
    binding_document = next(
        item
        for item in m4_snapshot.documents
        if item.kind == M4ProjectionArtifactKind.VERDICT_BINDING
    )
    record = HearingRecord.model_validate_json(record_document.canonical_document)
    binding = HearingVerdictBinding.model_validate_json(binding_document.canonical_document)
    pack = pending_case.evidence_packs[0]
    verdict = pending_case.verdicts[0]
    config = _bundle().config
    assert isinstance(config, AppConfig)
    references = assemble_m6_case_model_reference_authority(
        source_case=pending_case,
        m3_snapshot=m3_snapshot,
        m4_snapshot=m4_snapshot,
    )
    provisional_gate = M6ProceduralGateExecutionInput(
        source_review_id="provisional-m4-gate-review",
        source_review_document_sha256="0" * 64,
        verdict=verdict,
        evidence_pack=pack,
        current_closure=_current_closure(pack),
        gate_config=config.procedural_gate,
        alert_config=config.alerts,
        review_version=1,
    )
    review = provisional_gate.rebuild_review()
    case = Case.model_validate(
        {
            **pending_case.model_dump(mode="json", exclude_computed_fields=True),
            "status": (
                CaseStatus.READY_FOR_ALERT_POLICY.value
                if review.passed
                else CaseStatus.REWORK_REQUIRED.value
            ),
            "procedural_reviews": (review.model_dump(mode="json"),),
        }
    )
    gate_input = M6ProceduralGateExecutionInput(
        source_review_id=review.review_id,
        source_review_document_sha256=_document_sha256(review),
        verdict=verdict,
        evidence_pack=pack,
        current_closure=provisional_gate.current_closure,
        gate_config=provisional_gate.gate_config,
        alert_config=provisional_gate.alert_config,
        review_version=review.version,
    )
    gates = M6CaseProceduralGateAuthority(
        source_identity_sha256=m3_snapshot.source_identity_sha256,
        run_id=case.run_id,
        case_id=case.case_id,
        manifest_id=case.manifest_id,
        inputs=(gate_input,),
    )
    screening_calls = assemble_m6_locked_screening_model_calls(
        source_case=case,
        snapshot=m3_snapshot,
    )
    model_calls = tuple(
        sorted((*screening_calls, *_hearing_calls(record)), key=lambda item: item.sort_key)
    )
    retrieval_receipt = record.rounds[0].precedent_retrieval_receipt
    retrieval_cycles = (
        M6ResolvedRetrievalCycle(
            cycle_index=1,
            degraded_receipt=retrieval_receipt,
        ),
    )
    context = M6VerifiedProjectionContext(
        case=case,
        perception=_resolved_perception(case),
        historical_source_run_id=case.run_id,
        historical_source_case_id=case.case_id,
        historical_source_manifest_id=case.manifest_id,
        model_reference_authority=references,
        procedural_gate_authority=gates,
        model_responses=resolve_m6_locked_model_responses(model_calls),
        retrieval_cycles=retrieval_cycles,
    )
    case_document = canonical_json(case.model_dump(mode="json"))
    closure = M6ReplayInputClosureAuthority(
        sample_id="m4-gate-terminal-source-sample",
        source_run_id=case.run_id,
        source_case_id=case.case_id,
        source_case_revision=1,
        source_case_document_sha256=_sha(case_document),
        source_manifest_id=case.manifest_id,
        source_manifest_document_sha256=_sha("source manifest document"),
        input_authority_id=_sha("m4 source input authority"),
        input_authority_document_sha256=_sha("m4 source input document"),
        source_validation_report_id=_sha("m4 source validation report"),
        source_validation_report_document_sha256=_sha("m4 source validation document"),
        frames=tuple(
            M6LockedFrameInput(
                frame_id=item.frame_id,
                document_sha256=_document_sha256(item),
                content_sha256=item.content_sha256,
            )
            for item in context.perception.frames
            if item.content_sha256 is not None
        ),
        detections=tuple(
            M6LockedDetectionInput(
                detection_id=item.detection_id,
                frame_id=item.frame_id,
                document_sha256=_document_sha256(item),
                model_manifest_id=item.model_manifest_id,
            )
            for item in context.perception.detections
        ),
        model_calls=model_calls,
        historical_cut=M6HistoricalCausalCut(
            retrieval_cycles=(
                M6LockedRetrievalCycleInput(
                    source_run_id=case.run_id,
                    source_case_id=case.case_id,
                    hearing_session_id=record.hearing_session_id,
                    cycle_index=1,
                    cycle_scope_id=retrieval_receipt.cycle_scope_id,
                    outcome=M6LockedRetrievalOutcomeKind.DEGRADED,
                    authority_ref=M6ReplayAuthorityRef(
                        kind=(M6ReplayAuthorityKind.M4_PRECEDENT_RETRIEVAL_RECEIPT),
                        artifact_id=retrieval_receipt.receipt_id,
                        document_sha256=_document_sha256(retrieval_receipt),
                    ),
                ),
            )
        ),
    )
    receipt = M6GateCurrentClosureReceipt(
        run_id=case.run_id,
        case_id=case.case_id,
        manifest_id=case.manifest_id,
        review_version=review.version,
        source_review_id=review.review_id,
        source_review_document_sha256=_document_sha256(review),
        evidence_pack_id=pack.pack_id,
        evidence_pack_version=pack.version,
        evidence_pack_document_sha256=_document_sha256(pack),
        basis=M6GateCurrentClosureBasis.CURRENT_PRIVACY_CROP_REVERIFIED,
        current_closure=gate_input.current_closure,
        crop_verifications=tuple(
            sorted(
                (_verification(crop) for crop in pack.crops),
                key=lambda item: item.artifact_ref.sort_key,
            )
        ),
    )
    snapshot = build_m6_case_replay_snapshot(
        context=context,
        sample_id=closure.sample_id,
        source_case_revision=1,
    )
    return M6ReplayLockedM4GateTerminalSource(
        source_identity_sha256=m3_snapshot.source_identity_sha256,
        closure=closure,
        projection_context=context,
        hearing_record=record,
        hearing_verdict_binding=binding,
        gate_current_closure_receipt=receipt,
        source_snapshot=snapshot,
    )


def test_m4_gate_terminal_source_closes_the_first_single_round_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _terminal_source(monkeypatch)

    assert len(source.closure.model_calls) == 4
    assert source.closure.embeddings == ()
    assert source.closure.tool_results == ()
    assert source.hearing_record.version == 1
    assert len(source.hearing_record.rounds) == 1
    assert source.projection_context.retrieval_cycles[0].success_exposure is None


def test_m4_route_rejects_a_verdict_without_its_atomic_gate_review(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _terminal_source(monkeypatch)
    original = source.projection_context
    case = Case.model_validate(
        {
            **original.case.model_dump(mode="json", exclude_computed_fields=True),
            "status": CaseStatus.PROCEDURAL_REVIEW.value,
            "procedural_reviews": (),
        }
    )
    context = M6VerifiedProjectionContext(
        case=case,
        perception=original.perception,
        historical_source_run_id=original.historical_source_run_id,
        historical_source_case_id=original.historical_source_case_id,
        historical_source_manifest_id=original.historical_source_manifest_id,
        model_reference_authority=original.model_reference_authority,
        procedural_gate_authority=M6CaseProceduralGateAuthority(
            source_identity_sha256=source.source_identity_sha256,
            run_id=case.run_id,
            case_id=case.case_id,
            manifest_id=case.manifest_id,
        ),
        model_responses=original.model_responses,
        retrieval_cycles=original.retrieval_cycles,
    )
    snapshot = build_m6_case_replay_snapshot(
        context=context,
        sample_id=source.closure.sample_id,
        source_case_revision=1,
    )

    with pytest.raises(ValueError, match="first locked M4 plus Gate route"):
        M6ReplayLockedM4GateTerminalSource(
            source_identity_sha256=source.source_identity_sha256,
            closure=source.closure.model_copy(
                update={"source_case_document_sha256": snapshot.source_case_document_sha256}
            ),
            projection_context=context,
            hearing_record=source.hearing_record,
            hearing_verdict_binding=source.hearing_verdict_binding,
            gate_current_closure_receipt=source.gate_current_closure_receipt,
            source_snapshot=snapshot,
        )


def test_m4_route_rejects_success_retrieval_and_embedding_capabilities(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _terminal_source(monkeypatch)
    degraded = source.closure.historical_cut.retrieval_cycles[0]
    success_cut = M6HistoricalCausalCut(
        retrieval_cycles=(
            M6LockedRetrievalCycleInput(
                source_run_id=degraded.source_run_id,
                source_case_id=degraded.source_case_id,
                hearing_session_id=degraded.hearing_session_id,
                cycle_index=degraded.cycle_index,
                cycle_scope_id=degraded.cycle_scope_id,
                outcome=M6LockedRetrievalOutcomeKind.SUCCESS,
                authority_ref=M6ReplayAuthorityRef(
                    kind=M6ReplayAuthorityKind.M5_PRECEDENT_EXPOSURE,
                    artifact_id=_sha("foreign-success-exposure"),
                    document_sha256=_sha("foreign-success-exposure-document"),
                ),
            ),
        )
    )
    embedding = M6LockedEmbeddingInput(
        scope=M6LockedEmbeddingScope.QUERY,
        channel=M6LockedEmbeddingChannel.TEXT,
        embedding_ref=M6ReplayAuthorityRef(
            kind=M6ReplayAuthorityKind.M5_EMBEDDING,
            artifact_id=_sha("foreign-query-embedding"),
            document_sha256=_sha("foreign-query-embedding-document"),
        ),
        request_id=_sha("foreign-query-request"),
        model_manifest_id=_sha("foreign-embedding-model"),
    )

    for update in (
        {"historical_cut": success_cut},
        {"embeddings": (embedding,)},
    ):
        with pytest.raises(ValueError, match="first locked M4 plus Gate route"):
            M6ReplayLockedM4GateTerminalSource(
                source_identity_sha256=source.source_identity_sha256,
                closure=source.closure.model_copy(update=update),
                projection_context=source.projection_context,
                hearing_record=source.hearing_record,
                hearing_verdict_binding=source.hearing_verdict_binding,
                gate_current_closure_receipt=source.gate_current_closure_receipt,
                source_snapshot=source.source_snapshot,
            )


def test_m4_route_rejects_a_retry_or_failure_shaped_model_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _terminal_source(monkeypatch)
    first = source.closure.model_calls[0]
    retried = M6LockedModelCallInput.model_validate(
        {
            **first.model_dump(mode="json", exclude_computed_fields=True),
            "attempt_index": 1,
        }
    )
    calls = (retried, *source.closure.model_calls[1:])

    with pytest.raises(ValueError, match="cross-grafted"):
        M6ReplayLockedM4GateTerminalSource(
            source_identity_sha256=source.source_identity_sha256,
            closure=source.closure.model_copy(update={"model_calls": calls}),
            projection_context=source.projection_context,
            hearing_record=source.hearing_record,
            hearing_verdict_binding=source.hearing_verdict_binding,
            gate_current_closure_receipt=source.gate_current_closure_receipt,
            source_snapshot=source.source_snapshot,
        )


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("hearing_verdict_binding", "binding"),
        ("gate_current_closure_receipt", "receipt"),
        ("source_snapshot", "snapshot"),
    ),
)
def test_m4_route_rejects_terminal_authority_grafts(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    replacement: str,
) -> None:
    source = _terminal_source(monkeypatch)
    values = {
        "source_identity_sha256": source.source_identity_sha256,
        "closure": source.closure,
        "projection_context": source.projection_context,
        "hearing_record": source.hearing_record,
        "hearing_verdict_binding": source.hearing_verdict_binding,
        "gate_current_closure_receipt": source.gate_current_closure_receipt,
        "source_snapshot": source.source_snapshot,
    }
    replacements = {
        "binding": source.hearing_verdict_binding.model_copy(
            update={"hearing_record_id": "f" * 64}
        ),
        "receipt": source.gate_current_closure_receipt.model_copy(
            update={"evidence_pack_document_sha256": "e" * 64}
        ),
        "snapshot": source.source_snapshot.model_copy(update={"sample_id": "foreign-sample"}),
    }
    values[field] = replacements[replacement]

    with pytest.raises(ValueError):
        M6ReplayLockedM4GateTerminalSource(**values)
