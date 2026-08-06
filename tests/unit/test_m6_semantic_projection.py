"""M6 whitelist semantic projection over the frozen Case aggregate."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path

import pytest

from labcourt.application.m6_model_reference_authority import (
    assemble_m6_case_model_reference_authority,
)
from labcourt.contracts.alerts import AlertDecision
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.cases import Case, UsageSummary
from labcourt.contracts.config import (
    AlertConfig,
    NumericToleranceConfig,
    ProceduralGateConfig,
)
from labcourt.contracts.detections import Detection
from labcourt.contracts.enums import (
    AlertLevel,
    ArgumentStance,
    ArtifactKind,
    CaseStatus,
    JudgeDisposition,
    PrecedentSource,
    ProceduralDefectCode,
    ProceduralDefectOrigin,
    ProceduralField,
    ProceduralReasonCode,
    VlmRole,
)
from labcourt.contracts.events import CandidateEvent
from labcourt.contracts.evidence import EvidencePack
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.hearing_state import (
    HearingPrecedentDegradedReason,
    HearingPrecedentRetrievalReceipt,
    HearingPrecedentRetrievalStatus,
)
from labcourt.contracts.m5_precedent_usage import M5PrecedentExposureBatchAuthority
from labcourt.contracts.m6_regression import (
    M6RegressionCaseDisposition,
    M6RegressionCaseResult,
    M6RegressionStage,
)
from labcourt.contracts.m6_replay_locked import (
    M6LockedModelCallInput,
    M6LockedModelCallLayer,
    M6LockedModelCallResultKind,
    M6LockedModelRole,
    M6ReplayAuthorityKind,
    M6ReplayAuthorityRef,
)
from labcourt.contracts.references import parse_frame_id
from labcourt.contracts.storage import ArtifactRef, ClosureReport
from labcourt.contracts.verdicts import (
    Argument,
    JudgeResponse,
    ObjectiveClaim,
    ProceduralDefect,
    Verdict,
)
from labcourt.domain import m6_semantic_projection
from labcourt.domain.m6_model_reference_authority import (
    M6CaseModelReferenceAuthority,
    M6HearingRoleModelReferenceBinding,
    M6ModelReferenceScope,
    M6ScreeningModelReferenceBinding,
    M6VerdictModelReferenceBinding,
)
from labcourt.domain.m6_procedural_gate_authority import (
    M6CaseProceduralGateAuthority,
    M6ProceduralGateExecutionInput,
    build_m6_gate_precedent_resolutions,
)
from labcourt.domain.m6_semantic_projection import (
    M6ResolvedModelResponse,
    M6ResolvedPerception,
    M6ResolvedRetrievalCycle,
    M6VerifiedProjectionContext,
    build_m6_case_replay_snapshot,
    resolve_m6_locked_model_responses,
)
from labcourt.ports.m6_acquisition_authority import M6ValidatedM4ReplayAuthoritySnapshot
from tests.contract.test_m5_precedent_usage_contracts import (
    _default_applications,
    _exposure,
    _policy,
    _ready_case,
)
from tests.unit.test_m6_model_reference_authority import _fast_case, _repair_snapshot

FIXTURE_ROOT = Path(__file__).parents[1] / "fixtures" / "m2"


def _event(*, manifest_id: str | None = None, l1_score: float | None = None) -> CandidateEvent:
    payload = CandidateEvent.model_validate_json(
        (FIXTURE_ROOT / "candidate-event-presence.json").read_text(encoding="utf-8")
    ).model_dump(mode="json", exclude_computed_fields=True)
    if manifest_id is not None:
        payload["manifest_id"] = manifest_id
    if l1_score is not None:
        payload["l1_score"] = l1_score
    return CandidateEvent.model_validate(payload)


def _case(
    *,
    run_id: str = "baseline-run",
    manifest_id: str | None = None,
    l1_score: float | None = None,
    usage: UsageSummary | None = None,
    alerts: tuple[AlertDecision, ...] = (),
    legacy_semantic_hash: str | None = None,
) -> Case:
    event = _event(manifest_id=manifest_id, l1_score=l1_score)
    return Case(
        run_id=run_id,
        status=CaseStatus.CANDIDATE,
        event=event,
        manifest_id=event.manifest_id,
        usage=usage or UsageSummary(),
        alerts=alerts,
        semantic_case_hash=legacy_semantic_hash,
    )


def _stable_refs(refs: tuple[ArtifactRef, ...]) -> tuple[ArtifactRef, ...]:
    by_key = {ref.sort_key: ref for ref in refs}
    return tuple(by_key[key] for key in sorted(by_key))


def _pack_citable_refs(pack: EvidencePack) -> tuple[ArtifactRef, ...]:
    return _stable_refs(
        tuple(
            [
                *(
                    ArtifactRef(kind=ArtifactKind.FRAME, artifact_id=item)
                    for item in pack.key_frame_ids
                ),
                *(
                    ArtifactRef(kind=ArtifactKind.CROP, artifact_id=item.crop_id)
                    for item in pack.crops
                ),
                *(
                    ArtifactRef(kind=ArtifactKind.OBJECTIVE_FACT, artifact_id=item.fact_id)
                    for item in pack.objective_facts
                ),
                *(
                    ArtifactRef(kind=ArtifactKind.TOOL_RESULT, artifact_id=item.tool_result_id)
                    for item in pack.tool_results
                ),
            ]
        )
    )


def _verdict_binding(
    verdict: Verdict,
    *,
    cycle_scope_id: str,
    allowed_evidence_refs: tuple[ArtifactRef, ...] = (),
    allowed_precedent_refs: tuple[ArtifactRef, ...] = (),
    evidence_refs_by_role: dict[VlmRole, tuple[ArtifactRef, ...]] | None = None,
    precedent_refs_by_role: dict[VlmRole, tuple[ArtifactRef, ...]] | None = None,
    response_ids_by_role: dict[VlmRole, str] | None = None,
) -> M6VerdictModelReferenceBinding:
    evidence_by_role = evidence_refs_by_role or {}
    precedent_by_role = precedent_refs_by_role or {}
    response_by_role = response_ids_by_role or {}
    default_response_id = verdict.model_response_refs[0].artifact_id
    role_bindings = tuple(
        M6HearingRoleModelReferenceBinding(
            role=role,
            output_id=f"fixture-{role.value.lower()}-output-{verdict.verdict_id}",
            response_id=response_by_role.get(role, default_response_id),
            final_request_id=f"fixture-{role.value.lower()}-final-request-{verdict.verdict_id}",
            scope=M6ModelReferenceScope(
                request_id=f"fixture-{role.value.lower()}-scope-request-{verdict.verdict_id}",
                evidence_pack_id=verdict.evidence_pack_id,
                evidence_pack_version=verdict.evidence_pack_version,
                cycle_scope_id=cycle_scope_id,
                allowed_evidence_refs=_stable_refs(
                    evidence_by_role.get(role, allowed_evidence_refs)
                ),
                allowed_precedent_refs=_stable_refs(
                    precedent_by_role.get(role, allowed_precedent_refs)
                ),
            ),
        )
        for role in (VlmRole.PROSECUTOR, VlmRole.DEFENDER, VlmRole.JUDGE)
    )
    return M6VerdictModelReferenceBinding(
        verdict_id=verdict.verdict_id,
        hearing_record_id=f"fixture-hearing-record-{verdict.verdict_id}",
        judge_round_id=f"fixture-judge-round-{verdict.verdict_id}",
        role_bindings=role_bindings,
    )


def _model_reference_authority(
    case: Case,
    retrieval_cycles: tuple[M6ResolvedRetrievalCycle, ...],
    model_responses: tuple[M6ResolvedModelResponse, ...],
) -> M6CaseModelReferenceAuthority:
    packs_by_key = {(pack.pack_id, pack.version): pack for pack in case.evidence_packs}
    screening_bindings = tuple(
        sorted(
            (
                M6ScreeningModelReferenceBinding(
                    screening_id=screening.screening_id,
                    parsed_output_id=screening.parsed_output.parsed_output_id,
                    final_request_id=screening.parsed_output.request_id,
                    scope=M6ModelReferenceScope(
                        request_id=screening.parsed_output.request_id,
                        evidence_pack_id=screening.evidence_pack_id,
                        evidence_pack_version=screening.evidence_pack_version,
                        cycle_scope_id=None,
                        allowed_evidence_refs=_pack_citable_refs(
                            packs_by_key[
                                (
                                    screening.evidence_pack_id,
                                    screening.evidence_pack_version,
                                )
                            ]
                        ),
                    ),
                )
                for screening in case.screening_results
            ),
            key=lambda item: item.screening_id,
        )
    )
    response_roles = {
        VlmRole.PROSECUTOR: M6LockedModelRole.PROSECUTOR,
        VlmRole.DEFENDER: M6LockedModelRole.DEFENDER,
        VlmRole.JUDGE: M6LockedModelRole.JUDGE,
    }
    verdict_bindings: list[M6VerdictModelReferenceBinding] = []
    for verdict in case.verdicts:
        matching_cycles = tuple(
            cycle
            for cycle in retrieval_cycles
            if (
                (
                    cycle.success_exposure.m4_retrieval_outcome.receipt
                    if cycle.success_exposure is not None
                    else cycle.degraded_receipt
                ).current_evidence_pack_id
                == verdict.evidence_pack_id
                and (
                    cycle.success_exposure.m4_retrieval_outcome.receipt
                    if cycle.success_exposure is not None
                    else cycle.degraded_receipt
                ).current_evidence_pack_version
                == verdict.evidence_pack_version
            )
        )
        if not matching_cycles:
            raise AssertionError("fixture Verdict requires an exact retrieval cycle")
        cycle = matching_cycles[-1]
        allowed_precedent_refs = (
            _stable_refs(
                tuple(
                    ArtifactRef(
                        kind=ArtifactKind.PRECEDENT,
                        artifact_id=item.precedent_id,
                    )
                    for item in cycle.success_exposure.exposed_precedents
                )
            )
            if cycle.success_exposure is not None
            else ()
        )
        verdict_response_ids = {ref.artifact_id for ref in verdict.model_response_refs}
        response_ids_by_role: dict[VlmRole, str] = {}
        for role, locked_role in response_roles.items():
            matching_response = next(
                (
                    response.response_id
                    for response in model_responses
                    if response.role == locked_role and response.response_id in verdict_response_ids
                ),
                None,
            )
            if matching_response is not None:
                response_ids_by_role[role] = matching_response
        verdict_bindings.append(
            _verdict_binding(
                verdict,
                cycle_scope_id=cycle.cycle_scope_id,
                allowed_evidence_refs=_pack_citable_refs(
                    packs_by_key[(verdict.evidence_pack_id, verdict.evidence_pack_version)]
                ),
                allowed_precedent_refs=allowed_precedent_refs,
                response_ids_by_role=response_ids_by_role,
            )
        )
    return M6CaseModelReferenceAuthority(
        source_identity_sha256=sha256_hex(
            [
                "m6-test-model-reference-authority",
                case.run_id,
                case.case_id,
                case.manifest_id,
            ]
        ),
        run_id=case.run_id,
        case_id=case.case_id,
        manifest_id=case.manifest_id,
        screening_bindings=screening_bindings,
        verdict_bindings=tuple(sorted(verdict_bindings, key=lambda item: item.verdict_id)),
    )


def _gate_config() -> ProceduralGateConfig:
    return ProceduralGateConfig(
        objective_numeric_tolerance=NumericToleranceConfig(
            duration_frames=1,
            person_count=0,
            frame_interval_frames=1,
            track_presence_interval_frames=1,
            detection_score=0.01,
            observability=0.01,
        ),
        precedent_similarity_min=0.55,
        absence_clear_frame_threshold=0.65,
        minimum_absence_clear_frames=2,
    )


def _alert_config() -> AlertConfig:
    return AlertConfig(
        cooldown_seconds=30.0,
        repeat_window_days=7,
        confirmed_min_confidence=0.8,
        insufficient_evidence_max_level=AlertLevel.ADVISORY,
    )


def _current_closure(pack: EvidencePack) -> ClosureReport:
    root = ArtifactRef(kind=ArtifactKind.EVIDENCE_PACK, artifact_id=pack.pack_id)
    checked = {ref.sort_key: ref for ref in (*pack.expected_closure_refs(), root)}
    return ClosureReport(
        run_id=pack.run_id,
        root_ref=root,
        manifest_id=pack.manifest_id,
        input_sha256=pack.closure_input_sha256,
        checked_refs=tuple(checked[key] for key in sorted(checked)),
    )


def _gate_authority(
    case: Case,
    retrieval_cycles: tuple[M6ResolvedRetrievalCycle, ...],
) -> M6CaseProceduralGateAuthority:
    verdicts = {item.verdict_id: item for item in case.verdicts}
    packs = {(item.pack_id, item.version): item for item in case.evidence_packs}
    inputs: list[M6ProceduralGateExecutionInput] = []
    for review in case.procedural_reviews:
        verdict = verdicts[review.reviewed_verdict_id]
        pack = packs[(review.evidence_pack_id, review.evidence_pack_version)]
        matching_cycles = tuple(
            cycle
            for cycle in retrieval_cycles
            if (
                (
                    cycle.success_exposure.m4_retrieval_outcome.receipt
                    if cycle.success_exposure is not None
                    else cycle.degraded_receipt
                ).current_evidence_pack_id
                == pack.pack_id
                and (
                    cycle.success_exposure.m4_retrieval_outcome.receipt
                    if cycle.success_exposure is not None
                    else cycle.degraded_receipt
                ).current_evidence_pack_version
                == pack.version
            )
        )
        resolutions = ()
        if matching_cycles:
            cycle = matching_cycles[-1]
            receipt = (
                cycle.success_exposure.m4_retrieval_outcome.receipt
                if cycle.success_exposure is not None
                else cycle.degraded_receipt
            )
            assert receipt is not None
            resolutions = build_m6_gate_precedent_resolutions(
                evidence_pack=pack,
                receipt=receipt,
            )
        inputs.append(
            M6ProceduralGateExecutionInput(
                source_review_id=review.review_id,
                source_review_document_sha256=hashlib.sha256(
                    canonical_json(review.model_dump(mode="json")).encode("utf-8")
                ).hexdigest(),
                verdict=verdict,
                evidence_pack=pack,
                current_closure=_current_closure(pack),
                gate_config=_gate_config(),
                alert_config=_alert_config(),
                review_version=review.version,
                precedent_resolutions=resolutions,
            )
        )
    return M6CaseProceduralGateAuthority(
        source_identity_sha256=sha256_hex(
            [
                "m6-test-model-reference-authority",
                case.run_id,
                case.case_id,
                case.manifest_id,
            ]
        ),
        run_id=case.run_id,
        case_id=case.case_id,
        manifest_id=case.manifest_id,
        inputs=tuple(sorted(inputs, key=lambda item: item.sort_key)),
    )


def _snapshot(
    case: Case,
    *,
    revision: int = 1,
    retrieval_exposures: tuple[M5PrecedentExposureBatchAuthority, ...] = (),
    retrieval_cycles: tuple[M6ResolvedRetrievalCycle, ...] | None = None,
    perception: M6ResolvedPerception | None = None,
    model_responses: tuple[M6ResolvedModelResponse, ...] | None = None,
):
    if retrieval_cycles is not None:
        resolved_cycles = retrieval_cycles
    elif retrieval_exposures:
        resolved_cycles = tuple(
            M6ResolvedRetrievalCycle(
                cycle_index=exposure.cycle_index,
                success_exposure=exposure,
            )
            for exposure in retrieval_exposures
        )
    elif case.verdicts:
        resolved_cycles = (
            M6ResolvedRetrievalCycle(
                cycle_index=1,
                degraded_receipt=_degraded_receipt(
                    case,
                    HearingPrecedentDegradedReason.EMBEDDING_PROVIDER_UNAVAILABLE,
                ),
            ),
        )
    else:
        resolved_cycles = ()
    resolved_model_responses = (
        model_responses if model_responses is not None else _resolved_model_responses(case)
    )
    return build_m6_case_replay_snapshot(
        context=M6VerifiedProjectionContext(
            case=case,
            perception=perception or _resolved_perception(case),
            historical_source_run_id=case.run_id,
            historical_source_case_id=case.case_id,
            historical_source_manifest_id=case.manifest_id,
            model_reference_authority=_model_reference_authority(
                case,
                resolved_cycles,
                resolved_model_responses,
            ),
            procedural_gate_authority=_gate_authority(case, resolved_cycles),
            model_responses=resolved_model_responses,
            retrieval_cycles=resolved_cycles,
        ),
        sample_id="stable-sample-001",
        source_case_revision=revision,
    )


def _resolved_perception(
    case: Case,
    *,
    content_overrides: dict[str, str] | None = None,
) -> M6ResolvedPerception:
    frame_ids = {
        f"{case.event.camera_id}:{case.event.stream_id}:{case.event.start_frame}",
        f"{case.event.camera_id}:{case.event.stream_id}:{case.event.end_frame_exclusive - 1}",
        f"{case.event.camera_id}:{case.event.stream_id}:{case.event.trigger_frame}",
        *case.event.confirmation.examined_frame_ids,
        *case.event.confirmation.counterevidence_frame_ids,
    }
    if case.event.confirmation.post_threshold_recovery_frame_id is not None:
        frame_ids.add(case.event.confirmation.post_threshold_recovery_frame_id)
    for pack in case.evidence_packs:
        frame_ids.update(pack.key_frame_ids)
        frame_ids.update(crop.frame_id for crop in pack.crops)
    overrides = content_overrides or {}
    frames = []
    for frame_id in sorted(frame_ids, key=parse_frame_id):
        camera_id, stream_id, frame_index = parse_frame_id(frame_id)
        frames.append(
            FrameRef(
                camera_id=camera_id,
                stream_id=stream_id,
                frame_index=frame_index,
                fps_num=30,
                fps_den=1,
                width=1920,
                height=1080,
                content_sha256=overrides.get(
                    frame_id,
                    hashlib.sha256(frame_id.encode("utf-8")).hexdigest(),
                ),
            )
        )
    detections_by_id: dict[str, Detection] = {}
    for pack in case.evidence_packs:
        for crop in pack.crops:
            for ref in crop.source_refs:
                if ref.kind != ArtifactKind.DETECTION:
                    continue
                detection = Detection(
                    detection_id=ref.artifact_id,
                    frame_id=crop.frame_id,
                    label="fixture-source-object",
                    bbox=crop.bbox,
                    score=1.0,
                    track_ref=crop.primary_track_ref,
                    model_manifest_id=case.manifest_id,
                )
                previous = detections_by_id.get(ref.artifact_id)
                if previous is not None:
                    assert previous == detection
                detections_by_id[ref.artifact_id] = detection
    detections = tuple(
        sorted(
            detections_by_id.values(),
            key=lambda item: (parse_frame_id(item.frame_id), item.detection_id),
        )
    )
    return M6ResolvedPerception(frames=tuple(frames), detections=detections)


def _resolved_model_responses(
    case: Case,
    *,
    content_overrides: dict[str, str] | None = None,
) -> tuple[M6ResolvedModelResponse, ...]:
    overrides = content_overrides or {}
    responses: dict[str, M6ResolvedModelResponse] = {}
    for screening in case.screening_results:
        parsed = screening.parsed_output
        responses[parsed.response_id] = M6ResolvedModelResponse(
            layer=M6LockedModelCallLayer.SCREENING,
            role=M6LockedModelRole.SCREENING,
            attempt_index=0,
            response_id=parsed.response_id,
            raw_content_sha256=overrides.get(
                parsed.response_id,
                parsed.response_content_sha256,
            ),
        )
    for verdict in case.verdicts:
        for ref in verdict.model_response_refs:
            if ref.artifact_id in responses:
                continue
            responses[ref.artifact_id] = M6ResolvedModelResponse(
                layer=M6LockedModelCallLayer.HEARING,
                role=M6LockedModelRole.JUDGE,
                attempt_index=0,
                response_id=ref.artifact_id,
                raw_content_sha256=overrides.get(
                    ref.artifact_id,
                    hashlib.sha256(f"m6-test-response:{ref.artifact_id}".encode()).hexdigest(),
                ),
            )
    return tuple(sorted(responses.values(), key=lambda item: item.sort_key))


def _degraded_receipt(
    case: Case,
    reason: HearingPrecedentDegradedReason,
) -> HearingPrecedentRetrievalReceipt:
    pack = case.evidence_packs[0]
    return HearingPrecedentRetrievalReceipt(
        run_id=case.run_id,
        case_id=case.case_id,
        hearing_session_id="1" * 64,
        round_index=1,
        prior_acquisition_rounds=0,
        prior_rework_rounds=0,
        current_evidence_pack_id=pack.pack_id,
        current_evidence_pack_version=pack.version,
        evidence_class=case.event.evidence_class,
        violation_type=case.event.violation_type,
        rule_version=case.event.rule_version,
        top_k=4,
        query_sha256="2" * 64,
        candidate_snapshot_sha256="3" * 64,
        visible_snapshot_sha256="4" * 64,
        status=HearingPrecedentRetrievalStatus.DEGRADED,
        degraded_reason=reason,
        retriever_version="m6-fixture-retriever-v1",
        retriever_manifest_id="5" * 64,
        manifest_id=case.manifest_id,
    )


def test_projection_builds_exact_stage_order_and_binds_canonical_source_document() -> None:
    case = _case()

    snapshot = _snapshot(case)

    assert tuple(root.stage for root in snapshot.stage_roots) == tuple(M6RegressionStage)
    expected_document = canonical_json(case.model_dump(mode="json"))
    assert (
        snapshot.source_case_document_sha256
        == hashlib.sha256(expected_document.encode("utf-8")).hexdigest()
    )
    assert snapshot.source_run_id == case.run_id


def test_fast_terminal_verdict_projects_from_the_screening_scope_without_m4() -> None:
    m3_snapshot = _repair_snapshot()
    case = _fast_case(m3_snapshot)
    reference_authority = assemble_m6_case_model_reference_authority(
        source_case=case,
        m3_snapshot=m3_snapshot,
        m4_snapshot=M6ValidatedM4ReplayAuthoritySnapshot(
            source_identity_sha256=m3_snapshot.source_identity_sha256,
            run_id=case.run_id,
            documents=(),
        ),
    )
    model_responses = tuple(
        sorted(
            (
                M6ResolvedModelResponse(
                    layer=M6LockedModelCallLayer.SCREENING,
                    role=M6LockedModelRole.SCREENING,
                    attempt_index=item.response.attempt_index,
                    response_id=item.response.response_id,
                    raw_content_sha256=item.response.content_sha256,
                )
                for item in m3_snapshot.responses
            ),
            key=lambda item: item.sort_key,
        )
    )
    context = M6VerifiedProjectionContext(
        case=case,
        perception=_resolved_perception(case),
        historical_source_run_id=case.run_id,
        historical_source_case_id=case.case_id,
        historical_source_manifest_id=case.manifest_id,
        model_reference_authority=reference_authority,
        procedural_gate_authority=M6CaseProceduralGateAuthority(
            source_identity_sha256=m3_snapshot.source_identity_sha256,
            run_id=case.run_id,
            case_id=case.case_id,
            manifest_id=case.manifest_id,
            inputs=(),
        ),
        model_responses=model_responses,
        retrieval_cycles=(),
    )

    payloads = dict(m6_semantic_projection._stage_payloads(context))
    snapshot = build_m6_case_replay_snapshot(
        context=context,
        sample_id="fast-terminal-sample",
        source_case_revision=1,
    )
    projected = payloads[M6RegressionStage.HEARING]["verdicts"]

    assert isinstance(projected, list)
    assert projected[0]["route"] == "M3_FAST_TERMINAL_POST_PARSE"
    assert len(projected[0]["model_responses"]) == 2
    assert all("response_id" not in item for item in projected[0]["model_responses"])
    assert reference_authority.verdict_bindings == ()
    assert len(reference_authority.fast_verdict_bindings) == 1
    assert tuple(root.stage for root in snapshot.stage_roots) == tuple(M6RegressionStage)
    assert snapshot.source_case_id == case.case_id
    assert snapshot.manifest_id == case.manifest_id


def test_operational_identity_usage_and_legacy_hash_do_not_change_semantics() -> None:
    baseline = _snapshot(_case())
    operationally_different = _snapshot(
        _case(
            run_id="candidate-run",
            usage=UsageSummary(
                input_images=9,
                input_pixels=123_456,
                input_tokens=777,
                output_tokens=333,
                provider_latency_ms=98_765,
                retries=4,
                estimated_cost=12.5,
            ),
            legacy_semantic_hash="f" * 64,
        )
    )

    assert operationally_different.stage_roots == baseline.stage_roots
    assert operationally_different.semantic_case_hash == baseline.semantic_case_hash
    assert operationally_different.source_case_document_sha256 != (
        baseline.source_case_document_sha256
    )
    assert operationally_different.snapshot_id != baseline.snapshot_id


def test_run_scoped_model_response_id_is_resolved_to_content_semantics() -> None:
    source_case, source_verdict = _ready_case(())
    source_screening = source_case.screening_results[0]
    source_review = source_case.procedural_reviews[0]
    replacement_response_id = "e" * 64
    replacement_parsed = source_screening.parsed_output.model_copy(
        update={"response_id": replacement_response_id}
    )
    replacement_screening = source_screening.model_copy(
        update={"parsed_output": replacement_parsed}
    )
    replacement_verdict = source_verdict.model_copy(
        update={
            "screening_id": replacement_screening.screening_id,
            "model_response_refs": (
                ArtifactRef(
                    kind=ArtifactKind.MODEL_RESPONSE,
                    artifact_id=replacement_response_id,
                ),
            ),
        }
    )
    replacement_review = source_review.model_copy(
        update={
            "reviewed_verdict_id": replacement_verdict.verdict_id,
            "reviewed_verdict_sha256": replacement_verdict.verdict_sha256,
        }
    )
    replacement_case = source_case.model_copy(
        update={
            "screening_results": (replacement_screening,),
            "verdicts": (replacement_verdict,),
            "procedural_reviews": (replacement_review,),
        }
    )

    baseline = _snapshot(source_case)
    candidate = _snapshot(replacement_case)

    assert candidate.source_case_document_sha256 != baseline.source_case_document_sha256
    assert candidate.stage_roots == baseline.stage_roots
    assert candidate.semantic_case_hash == baseline.semantic_case_hash


def test_multiple_model_responses_use_semantic_not_raw_id_order() -> None:
    source_case, source_verdict = _ready_case(())

    def case_with_response_ids(response_ids: tuple[str, ...]) -> Case:
        refs = tuple(
            ArtifactRef(kind=ArtifactKind.MODEL_RESPONSE, artifact_id=response_id)
            for response_id in sorted(response_ids)
        )
        verdict = source_verdict.model_copy(update={"model_response_refs": refs})
        review = source_case.procedural_reviews[0].model_copy(
            update={
                "reviewed_verdict_id": verdict.verdict_id,
                "reviewed_verdict_sha256": verdict.verdict_sha256,
            }
        )
        return source_case.model_copy(
            update={"verdicts": (verdict,), "procedural_reviews": (review,)}
        )

    baseline_case = case_with_response_ids(("1" * 64, "2" * 64))
    candidate_case = case_with_response_ids(("4" * 64, "3" * 64))
    screening_response = _resolved_model_responses(source_case)[0]
    baseline_responses = tuple(
        sorted(
            (
                screening_response,
                M6ResolvedModelResponse(
                    layer=M6LockedModelCallLayer.HEARING,
                    role=M6LockedModelRole.PROSECUTOR,
                    attempt_index=0,
                    response_id="1" * 64,
                    raw_content_sha256="a" * 64,
                ),
                M6ResolvedModelResponse(
                    layer=M6LockedModelCallLayer.HEARING,
                    role=M6LockedModelRole.JUDGE,
                    attempt_index=0,
                    response_id="2" * 64,
                    raw_content_sha256="b" * 64,
                ),
            ),
            key=lambda item: item.sort_key,
        )
    )
    candidate_responses = tuple(
        sorted(
            (
                screening_response,
                M6ResolvedModelResponse(
                    layer=M6LockedModelCallLayer.HEARING,
                    role=M6LockedModelRole.PROSECUTOR,
                    attempt_index=0,
                    response_id="4" * 64,
                    raw_content_sha256="a" * 64,
                ),
                M6ResolvedModelResponse(
                    layer=M6LockedModelCallLayer.HEARING,
                    role=M6LockedModelRole.JUDGE,
                    attempt_index=0,
                    response_id="3" * 64,
                    raw_content_sha256="b" * 64,
                ),
            ),
            key=lambda item: item.sort_key,
        )
    )

    baseline = _snapshot(baseline_case, model_responses=baseline_responses)
    candidate = _snapshot(candidate_case, model_responses=candidate_responses)

    assert candidate.source_case_document_sha256 != baseline.source_case_document_sha256
    assert candidate.stage_roots == baseline.stage_roots
    assert candidate.semantic_case_hash == baseline.semantic_case_hash


def test_hearing_response_content_change_moves_hearing_root_without_hashing_raw_id() -> None:
    source_case, source_verdict = _ready_case(())
    hearing_response_id = "f" * 64
    refs = tuple(
        sorted(
            (
                *source_verdict.model_response_refs,
                ArtifactRef(
                    kind=ArtifactKind.MODEL_RESPONSE,
                    artifact_id=hearing_response_id,
                ),
            ),
            key=lambda item: item.sort_key,
        )
    )
    verdict = source_verdict.model_copy(update={"model_response_refs": refs})
    review = source_case.procedural_reviews[0].model_copy(
        update={
            "reviewed_verdict_id": verdict.verdict_id,
            "reviewed_verdict_sha256": verdict.verdict_sha256,
        }
    )
    case = source_case.model_copy(update={"verdicts": (verdict,), "procedural_reviews": (review,)})
    baseline_responses = _resolved_model_responses(
        case,
        content_overrides={hearing_response_id: "a" * 64},
    )
    candidate_responses = _resolved_model_responses(
        case,
        content_overrides={hearing_response_id: "b" * 64},
    )

    baseline = _snapshot(case, model_responses=baseline_responses)
    candidate = _snapshot(case, model_responses=candidate_responses)

    changed = tuple(
        candidate_root.stage
        for baseline_root, candidate_root in zip(
            baseline.stage_roots,
            candidate.stage_roots,
            strict=True,
        )
        if baseline_root != candidate_root
    )
    assert changed == (M6RegressionStage.HEARING,)


def test_projection_context_rejects_missing_model_response_authority() -> None:
    case, _ = _ready_case(())
    cycle = M6ResolvedRetrievalCycle(
        cycle_index=1,
        degraded_receipt=_degraded_receipt(
            case,
            HearingPrecedentDegradedReason.EMBEDDING_PROVIDER_UNAVAILABLE,
        ),
    )

    with pytest.raises(ValueError, match="response authority is missing"):
        M6VerifiedProjectionContext(
            case=case,
            perception=_resolved_perception(case),
            historical_source_run_id=case.run_id,
            historical_source_case_id=case.case_id,
            historical_source_manifest_id=case.manifest_id,
            model_reference_authority=_model_reference_authority(case, (cycle,), ()),
            procedural_gate_authority=_gate_authority(case, (cycle,)),
            retrieval_cycles=(cycle,),
        )


def test_projection_context_rejects_case_from_another_historical_run() -> None:
    case = _case()

    with pytest.raises(ValueError, match="historical source scope"):
        M6VerifiedProjectionContext(
            case=case,
            perception=_resolved_perception(case),
            historical_source_run_id="foreign-run",
            historical_source_case_id=case.case_id,
            historical_source_manifest_id=case.manifest_id,
            model_reference_authority=_model_reference_authority(case, (), ()),
            procedural_gate_authority=_gate_authority(case, ()),
        )


def test_locked_model_call_resolves_run_scoped_id_to_semantic_response() -> None:
    def authority(
        kind: M6ReplayAuthorityKind,
        artifact_id: str,
        document_character: str,
    ) -> M6ReplayAuthorityRef:
        return M6ReplayAuthorityRef(
            kind=kind,
            artifact_id=artifact_id,
            document_sha256=document_character * 64,
        )

    call = M6LockedModelCallInput(
        layer=M6LockedModelCallLayer.SCREENING,
        role=M6LockedModelRole.SCREENING,
        attempt_index=0,
        request_ref=authority(
            M6ReplayAuthorityKind.M3_MODEL_REQUEST,
            "screening-request",
            "1",
        ),
        result_kind=M6LockedModelCallResultKind.RESPONSE,
        response_ref=authority(
            M6ReplayAuthorityKind.M3_MODEL_RESPONSE,
            "a" * 64,
            "2",
        ),
        cache_ref=authority(
            M6ReplayAuthorityKind.M3_MODEL_CACHE,
            "screening-cache",
            "3",
        ),
        parse_receipt_ref=authority(
            M6ReplayAuthorityKind.M3_PARSE_RECEIPT,
            "screening-parse",
            "4",
        ),
        raw_content_sha256="b" * 64,
        raw_size_bytes=321,
    )

    responses = resolve_m6_locked_model_responses((call,))

    assert responses == (
        M6ResolvedModelResponse(
            layer=M6LockedModelCallLayer.SCREENING,
            role=M6LockedModelRole.SCREENING,
            attempt_index=0,
            response_id="a" * 64,
            raw_content_sha256="b" * 64,
        ),
    )
    assert "response_id" not in responses[0].semantic_projection()


def test_source_revision_changes_snapshot_identity_but_not_case_semantics() -> None:
    case = _case()

    first = _snapshot(case, revision=1)
    later = _snapshot(case, revision=7)

    assert later.stage_roots == first.stage_roots
    assert later.semantic_case_hash == first.semantic_case_hash
    assert later.snapshot_id != first.snapshot_id


def test_manifest_only_change_is_not_fabricated_as_a_stage_divergence() -> None:
    baseline = _snapshot(_case(manifest_id="a" * 64))
    candidate = _snapshot(
        _case(run_id="candidate-run", manifest_id="b" * 64),
    )

    result = M6RegressionCaseResult(
        entry_id="c" * 64,
        sample_id=baseline.sample_id,
        baseline_snapshot=baseline,
        candidate_snapshot=candidate,
    )

    assert candidate.stage_roots == baseline.stage_roots
    assert candidate.semantic_case_hash != baseline.semantic_case_hash
    assert result.behavior_identical is True
    assert result.first_divergence_stage is None
    assert result.disposition == M6RegressionCaseDisposition.MANIFEST_ONLY_CHANGE


def test_perception_change_only_moves_the_perception_stage_root() -> None:
    baseline = _snapshot(_case(l1_score=0.25))
    candidate = _snapshot(_case(run_id="candidate-run", l1_score=0.75))

    changed = tuple(
        candidate_root.stage
        for baseline_root, candidate_root in zip(
            baseline.stage_roots,
            candidate.stage_roots,
            strict=True,
        )
        if baseline_root != candidate_root
    )
    result = M6RegressionCaseResult(
        entry_id="d" * 64,
        sample_id=baseline.sample_id,
        baseline_snapshot=baseline,
        candidate_snapshot=candidate,
    )

    assert changed == (M6RegressionStage.PERCEPTION,)
    assert result.first_divergence_stage == M6RegressionStage.PERCEPTION
    assert result.disposition == M6RegressionCaseDisposition.SEMANTIC_DRIFT


def test_frame_content_change_only_moves_the_perception_stage_root() -> None:
    case = _case()
    baseline_perception = _resolved_perception(case)
    changed_frame_id = baseline_perception.frames[0].frame_id
    candidate_perception = _resolved_perception(
        case,
        content_overrides={changed_frame_id: "f" * 64},
    )

    baseline = _snapshot(case, perception=baseline_perception)
    candidate = _snapshot(case, perception=candidate_perception)

    changed = tuple(
        candidate_root.stage
        for baseline_root, candidate_root in zip(
            baseline.stage_roots,
            candidate.stage_roots,
            strict=True,
        )
        if baseline_root != candidate_root
    )
    assert changed == (M6RegressionStage.PERCEPTION,)


def test_detection_geometry_is_semantic_but_model_manifest_identity_is_not() -> None:
    case = _case()
    base = _resolved_perception(case)
    frame_id = base.frames[0].frame_id
    detection = Detection(
        detection_id="detection-semantic-001",
        frame_id=frame_id,
        label="person",
        bbox=BBoxXYXY(x1=10, y1=20, x2=110, y2=220),
        score=0.9,
        model_manifest_id="a" * 64,
    )
    same_detection_new_manifest = detection.model_copy(update={"model_manifest_id": "b" * 64})
    same_detection_new_identity = detection.model_copy(
        update={"detection_id": "detection-semantic-002"}
    )
    same_detection_new_provider_metadata = detection.model_copy(
        update={
            "attributes": {
                "observation_source": "provider-b",
                "pose_source": "pose-provider-b",
                "source_label": "provider-person-v2",
            }
        }
    )
    semantic_attribute_change = detection.model_copy(update={"attributes": {"cap_detected": False}})
    moved_detection = detection.model_copy(update={"bbox": BBoxXYXY(x1=11, y1=20, x2=110, y2=220)})

    baseline = _snapshot(
        case,
        perception=M6ResolvedPerception(frames=base.frames, detections=(detection,)),
    )
    manifest_only = _snapshot(
        case,
        perception=M6ResolvedPerception(
            frames=base.frames,
            detections=(same_detection_new_manifest,),
        ),
    )
    identity_only = _snapshot(
        case,
        perception=M6ResolvedPerception(
            frames=base.frames,
            detections=(same_detection_new_identity,),
        ),
    )
    provider_metadata_only = _snapshot(
        case,
        perception=M6ResolvedPerception(
            frames=base.frames,
            detections=(same_detection_new_provider_metadata,),
        ),
    )
    semantic_attribute = _snapshot(
        case,
        perception=M6ResolvedPerception(
            frames=base.frames,
            detections=(semantic_attribute_change,),
        ),
    )
    moved = _snapshot(
        case,
        perception=M6ResolvedPerception(frames=base.frames, detections=(moved_detection,)),
    )

    assert manifest_only.stage_roots == baseline.stage_roots
    assert identity_only.stage_roots == baseline.stage_roots
    assert provider_metadata_only.stage_roots == baseline.stage_roots
    changed = tuple(
        moved_root.stage
        for baseline_root, moved_root in zip(
            baseline.stage_roots,
            moved.stage_roots,
            strict=True,
        )
        if baseline_root != moved_root
    )
    assert changed == (M6RegressionStage.PERCEPTION,)
    assert semantic_attribute.stage_roots != baseline.stage_roots


def test_tracker_alias_rename_is_operational_but_track_association_is_semantic() -> None:
    case = _case()
    base = _resolved_perception(case)
    first_frame, second_frame = base.frames[:2]
    first = Detection(
        detection_id="track-detection-001",
        frame_id=first_frame.frame_id,
        label="person",
        bbox=BBoxXYXY(x1=10, y1=20, x2=110, y2=220),
        score=0.9,
        track_ref=f"{first_frame.camera_id}:tracker-epoch-a:local-7",
        model_manifest_id="a" * 64,
    )
    second = Detection(
        detection_id="track-detection-002",
        frame_id=second_frame.frame_id,
        label="person",
        bbox=BBoxXYXY(x1=12, y1=20, x2=112, y2=220),
        score=0.88,
        track_ref=f"{second_frame.camera_id}:tracker-epoch-a:local-7",
        model_manifest_id="a" * 64,
    )
    renamed_ref = f"{first_frame.camera_id}:tracker-epoch-b:local-99"
    renamed = (
        first.model_copy(update={"track_ref": renamed_ref}),
        second.model_copy(update={"track_ref": renamed_ref}),
    )
    split = (
        first,
        second.model_copy(
            update={"track_ref": f"{second_frame.camera_id}:tracker-epoch-a:local-8"}
        ),
    )

    baseline = _snapshot(
        case,
        perception=M6ResolvedPerception(frames=base.frames, detections=(first, second)),
    )
    alias_only = _snapshot(
        case,
        perception=M6ResolvedPerception(frames=base.frames, detections=renamed),
    )
    association_changed = _snapshot(
        case,
        perception=M6ResolvedPerception(frames=base.frames, detections=split),
    )

    assert alias_only.stage_roots == baseline.stage_roots
    assert alias_only.semantic_case_hash == baseline.semantic_case_hash
    changed = tuple(
        candidate_root.stage
        for baseline_root, candidate_root in zip(
            baseline.stage_roots,
            association_changed.stage_roots,
            strict=True,
        )
        if baseline_root != candidate_root
    )
    assert changed == (M6RegressionStage.PERCEPTION,)


def test_objective_fact_identity_is_operational_but_fact_value_is_semantic() -> None:
    case = _case()
    fact = case.event.objective_facts[0]
    renamed_event = case.event.model_copy(
        update={"objective_facts": (fact.model_copy(update={"fact_id": "renamed-objective-fact"}),)}
    )
    changed_event = case.event.model_copy(
        update={"objective_facts": (fact.model_copy(update={"value": int(fact.value) + 1}),)}
    )
    renamed_case = case.model_copy(update={"event": renamed_event})
    changed_case = case.model_copy(update={"event": changed_event})

    baseline = _snapshot(case)
    identity_only = _snapshot(renamed_case)
    semantic_change = _snapshot(changed_case)

    assert identity_only.source_case_document_sha256 != baseline.source_case_document_sha256
    assert identity_only.stage_roots == baseline.stage_roots
    assert identity_only.semantic_case_hash == baseline.semantic_case_hash
    assert semantic_change.stage_roots != baseline.stage_roots


def test_precedent_projection_excludes_opaque_precedent_identity() -> None:
    precedent = _exposure().exposed_precedents[0].historical_authority.precedent
    renamed = precedent.model_copy(update={"precedent_id": "renamed-precedent"})

    assert m6_semantic_projection._precedent(renamed) == (
        m6_semantic_projection._precedent(precedent)
    )


def test_automatic_precedent_situation_excludes_source_case_and_fact_aliases() -> None:
    template = _exposure().exposed_precedents[0].historical_authority.precedent
    fact = _case().event.objective_facts[0]

    def situation(alias: str) -> str:
        claim = ObjectiveClaim(
            kind=fact.kind,
            value=fact.value,
            evidence_ref=ArtifactRef(
                kind=ArtifactKind.OBJECTIVE_FACT,
                artifact_id=f"fact-{alias}",
            ),
        )
        return canonical_json(
            {
                "schema_version": "m5-automatic-precedent-situation-v1",
                "case_id": f"case-{alias}",
                "violation_type": template.violation_type.value,
                "evidence_class": template.evidence_class.value,
                "rule_version": template.rule_version,
                "verdict_id": alias * 64,
                "verdict_version": 1,
                "verdict_sha256": alias * 64,
                "decision": template.decision_direction.value,
                "rationale_summary": "The semantic rationale is unchanged.",
                "objective_claims": [claim.model_dump(mode="json")],
                "observation_sufficiency": None,
            }
        )

    baseline = template.model_copy(
        update={
            "precedent_id": "automatic-precedent-a",
            "situation_text": situation("a"),
            "source": PrecedentSource.AUTOMATIC,
            "source_case_id": "case-a",
        }
    )
    candidate = template.model_copy(
        update={
            "precedent_id": "automatic-precedent-b",
            "situation_text": situation("b"),
            "source": PrecedentSource.AUTOMATIC,
            "source_case_id": "case-b",
        }
    )

    assert m6_semantic_projection._precedent(candidate) == (
        m6_semantic_projection._precedent(baseline)
    )


def test_hearing_argument_aliases_and_judge_links_use_semantic_identity() -> None:
    source_case, source_verdict = _ready_case(())
    first_ref = ArtifactRef(
        kind=ArtifactKind.OBJECTIVE_FACT,
        artifact_id="fact-alias-a",
    )
    second_ref = ArtifactRef(
        kind=ArtifactKind.OBJECTIVE_FACT,
        artifact_id="fact-alias-b",
    )

    def verdict_with(ref: ArtifactRef):
        defense = Argument(
            stance=ArgumentStance.DEFENSE,
            claim="The same normalized fact supports this defense.",
            evidence_refs=(ref,),
            uncertainty=0.2,
        )
        response = JudgeResponse(
            defense_argument_id=defense.argument_id,
            disposition=JudgeDisposition.REJECTED,
            response_summary="The same semantic defense is answered.",
        )
        return source_verdict.model_copy(
            update={
                "defense_arguments": (defense,),
                "judge_responses": (response,),
            }
        )

    fact_semantic_sha256 = "f" * 64
    authorities = m6_semantic_projection._M6SemanticAuthorityIndex(
        tracks=m6_semantic_projection.M6SemanticTrackIndex(entries=()),
        acquisitions_by_id={},
        acquisition_projections_by_id={},
        acquisition_sha256_by_id={},
        artifact_sha256_by_key={
            (ArtifactKind.OBJECTIVE_FACT, first_ref.artifact_id): fact_semantic_sha256,
            (ArtifactKind.OBJECTIVE_FACT, second_ref.artifact_id): fact_semantic_sha256,
        },
    )
    responses = {item.response_id: item for item in _resolved_model_responses(source_case)}
    baseline_verdict = verdict_with(first_ref)
    renamed_verdict = verdict_with(second_ref)
    allowed_refs = _stable_refs((first_ref, second_ref))
    baseline_binding = _verdict_binding(
        baseline_verdict,
        cycle_scope_id="fixture-direct-hearing-cycle",
        allowed_evidence_refs=allowed_refs,
    )
    renamed_binding = _verdict_binding(
        renamed_verdict,
        cycle_scope_id="fixture-direct-hearing-cycle",
        allowed_evidence_refs=allowed_refs,
    )

    baseline = m6_semantic_projection._hearing(
        baseline_verdict,
        responses,
        authorities,
        baseline_binding,
    )
    renamed = m6_semantic_projection._hearing(
        renamed_verdict,
        responses,
        authorities,
        renamed_binding,
    )

    assert renamed == baseline
    assert m6_semantic_projection._defense_cardinality_semantics(
        renamed_verdict,
        authorities,
        renamed_binding.scope_for_role(VlmRole.DEFENDER),
    ) == m6_semantic_projection._defense_cardinality_semantics(
        baseline_verdict,
        authorities,
        baseline_binding.scope_for_role(VlmRole.DEFENDER),
    )


def test_hearing_prosecutor_cannot_borrow_judge_evidence_scope() -> None:
    source_case, source_verdict = _ready_case(())
    judge_only_ref = ArtifactRef(
        kind=ArtifactKind.OBJECTIVE_FACT,
        artifact_id="judge-only-fact",
    )
    prosecution = Argument(
        stance=ArgumentStance.PROSECUTION,
        claim="This reference was disclosed only to the Judge.",
        evidence_refs=(judge_only_ref,),
        uncertainty=0.1,
    )
    verdict = source_verdict.model_copy(update={"prosecution_arguments": (prosecution,)})
    authorities = m6_semantic_projection._M6SemanticAuthorityIndex(
        tracks=m6_semantic_projection.M6SemanticTrackIndex(entries=()),
        acquisitions_by_id={},
        acquisition_projections_by_id={},
        acquisition_sha256_by_id={},
        artifact_sha256_by_key={
            (judge_only_ref.kind, judge_only_ref.artifact_id): "a" * 64,
        },
    )
    binding = _verdict_binding(
        verdict,
        cycle_scope_id="fixture-role-isolation-cycle",
        evidence_refs_by_role={
            VlmRole.PROSECUTOR: (),
            VlmRole.DEFENDER: (),
            VlmRole.JUDGE: (judge_only_ref,),
        },
    )

    projection = m6_semantic_projection._hearing(
        verdict,
        {item.response_id: item for item in _resolved_model_responses(source_case)},
        authorities,
        binding,
    )

    assert projection["prosecution_arguments"][0]["evidence_refs"] == [
        {"kind": ArtifactKind.OBJECTIVE_FACT.value, "resolution": "UNRESOLVED"}
    ]


def test_precedent_reference_resolution_is_exactly_cycle_scoped() -> None:
    precedent_ref = ArtifactRef(
        kind=ArtifactKind.PRECEDENT,
        artifact_id="same-precedent-id",
    )
    authorities = m6_semantic_projection._M6SemanticAuthorityIndex(
        tracks=m6_semantic_projection.M6SemanticTrackIndex(entries=()),
        acquisitions_by_id={},
        acquisition_projections_by_id={},
        acquisition_sha256_by_id={},
        artifact_sha256_by_key={},
        precedent_sha256_by_scope_key={
            ("cycle-a", precedent_ref.artifact_id): "a" * 64,
            ("cycle-b", precedent_ref.artifact_id): "b" * 64,
        },
    )

    def scope(cycle_scope_id: str, *, exposed: bool = True) -> M6ModelReferenceScope:
        return M6ModelReferenceScope(
            request_id=f"request-{cycle_scope_id}",
            evidence_pack_id="fixture-pack",
            evidence_pack_version=1,
            cycle_scope_id=cycle_scope_id,
            allowed_evidence_refs=(),
            allowed_precedent_refs=(precedent_ref,) if exposed else (),
        )

    assert m6_semantic_projection._semantic_model_ref(
        precedent_ref,
        scope("cycle-a"),
        authorities,
    ) == {"kind": ArtifactKind.PRECEDENT.value, "projection_sha256": "a" * 64}
    assert m6_semantic_projection._semantic_model_ref(
        precedent_ref,
        scope("cycle-b"),
        authorities,
    ) == {"kind": ArtifactKind.PRECEDENT.value, "projection_sha256": "b" * 64}
    assert m6_semantic_projection._semantic_model_ref(
        precedent_ref,
        scope("cycle-a", exposed=False),
        authorities,
    ) == {"kind": ArtifactKind.PRECEDENT.value, "resolution": "UNRESOLVED"}


def test_fabricated_reference_token_hash_is_not_a_semantic_gate_value() -> None:
    _source_case, verdict = _ready_case(())
    authorities = m6_semantic_projection._M6SemanticAuthorityIndex(
        tracks=m6_semantic_projection.M6SemanticTrackIndex(entries=()),
        acquisitions_by_id={},
        acquisition_projections_by_id={},
        acquisition_sha256_by_id={},
        artifact_sha256_by_key={},
    )
    binding = _verdict_binding(
        verdict,
        cycle_scope_id="fixture-direct-defect-cycle",
    )

    def defect(value_sha256: str) -> ProceduralDefect:
        return ProceduralDefect(
            code=ProceduralDefectCode.FABRICATED_EVIDENCE_REFERENCE,
            origin=ProceduralDefectOrigin.PROCEDURAL_GATE,
            reason_code=ProceduralReasonCode.REFERENCE_NOT_ALLOWED,
            artifact_ref=ArtifactRef(
                kind=ArtifactKind.VERDICT,
                artifact_id=verdict.verdict_id,
            ),
            field=ProceduralField.EVIDENCE_REFERENCE,
            value_sha256=value_sha256,
        )

    baseline = m6_semantic_projection._defect(
        defect("a" * 64),
        verdict,
        authorities,
        binding,
    )
    candidate = m6_semantic_projection._defect(
        defect("b" * 64),
        verdict,
        authorities,
        binding,
    )

    assert candidate == baseline
    assert baseline["semantic_value"] == {
        "category": "UNRESOLVED_MODEL_REFERENCE",
        "namespace": "EVIDENCE",
    }


def test_gate_rebuild_ignores_missing_or_forged_persisted_cardinality_defect() -> None:
    source_case, source_verdict = _ready_case(())
    defense = Argument(
        stance=ArgumentStance.DEFENSE,
        claim="This defense point requires exactly one Judge response.",
        uncertainty=0.3,
    )
    verdict = source_verdict.model_copy(
        update={"defense_arguments": (defense,), "judge_responses": ()}
    )
    authorities = m6_semantic_projection._M6SemanticAuthorityIndex(
        tracks=m6_semantic_projection.M6SemanticTrackIndex(entries=()),
        acquisitions_by_id={},
        acquisition_projections_by_id={},
        acquisition_sha256_by_id={},
        artifact_sha256_by_key={},
    )
    binding = _verdict_binding(
        verdict,
        cycle_scope_id="fixture-direct-gate-cycle",
    )

    pack = source_case.evidence_packs[0]

    def execution_input(source_review_id: str, source_hash: str):
        return M6ProceduralGateExecutionInput(
            source_review_id=source_review_id,
            source_review_document_sha256=source_hash,
            verdict=verdict,
            evidence_pack=pack,
            current_closure=_current_closure(pack),
            gate_config=_gate_config(),
            alert_config=_alert_config(),
            review_version=verdict.version,
        )

    missing = m6_semantic_projection._gate(
        execution_input("missing-source-review", "a" * 64),
        authorities,
        binding,
    )
    forged = m6_semantic_projection._gate(
        execution_input("forged-source-review", "f" * 64),
        authorities,
        binding,
    )

    assert forged == missing
    assert missing["passed"] is False
    cardinality = tuple(
        defect
        for defect in missing["defects"]
        if defect["code"] == ProceduralDefectCode.UNANSWERED_DEFENSE_POINT.value
        and defect["reason_code"] == ProceduralReasonCode.DEFENSE_RESPONSE_CARDINALITY.value
    )
    assert len(cardinality) == 1


def test_policy_projection_and_highest_level_ignore_rescinded_alert_for_gate_summary() -> None:
    baseline = _snapshot(_case())
    confirmed = AlertDecision(
        alert_id="alert-confirmed",
        case_id=_case().case_id,
        level=AlertLevel.CONFIRMED,
        recipients=("lab-supervisor",),
        policy_rule_ids=("rule-confirmed",),
    )
    rescinded_emergency = AlertDecision(
        alert_id="alert-rescinded-emergency",
        case_id=_case().case_id,
        level=AlertLevel.EMERGENCY,
        recipients=("safety-officer",),
        policy_rule_ids=("rule-emergency",),
        rescinded=True,
    )
    candidate = _snapshot(
        _case(
            run_id="candidate-run",
            alerts=(confirmed, rescinded_emergency),
        )
    )

    changed = tuple(
        candidate_root.stage
        for baseline_root, candidate_root in zip(
            baseline.stage_roots,
            candidate.stage_roots,
            strict=True,
        )
        if baseline_root != candidate_root
    )

    assert changed == (M6RegressionStage.POLICY,)
    assert candidate.highest_alert_level == AlertLevel.CONFIRMED


def test_policy_recipient_rule_and_alert_collection_order_are_not_semantic() -> None:
    case = _case()
    first = AlertDecision(
        alert_id="alert-order-a",
        case_id=case.case_id,
        level=AlertLevel.ADVISORY,
        recipients=("operator-a", "operator-b"),
        policy_rule_ids=("rule-a", "rule-b"),
    )
    second = AlertDecision(
        alert_id="alert-order-b",
        case_id=case.case_id,
        level=AlertLevel.CONFIRMED,
        recipients=("supervisor",),
        policy_rule_ids=("rule-confirmed",),
    )
    reordered_first = first.model_copy(
        update={
            "recipients": tuple(reversed(first.recipients)),
            "policy_rule_ids": tuple(reversed(first.policy_rule_ids)),
        }
    )

    baseline = _snapshot(case.model_copy(update={"alerts": (first, second)}))
    reordered = _snapshot(case.model_copy(update={"alerts": (second, reordered_first)}))

    assert reordered.stage_roots == baseline.stage_roots
    assert reordered.semantic_case_hash == baseline.semantic_case_hash


def test_historical_exposure_change_moves_only_the_retrieval_stage_root() -> None:
    baseline_policy = _policy()
    changed_source_weights = dict(baseline_policy.source_weights)
    changed_source_weights[PrecedentSource.APPEAL_OVERTURN] = 1.1
    candidate_policy = baseline_policy.model_copy(update={"source_weights": changed_source_weights})
    baseline_exposure = _exposure(policy=baseline_policy)
    candidate_exposure = _exposure(policy=candidate_policy)
    case, _verdict = _ready_case(())

    baseline = _snapshot(case, retrieval_exposures=(baseline_exposure,))
    candidate = _snapshot(case, retrieval_exposures=(candidate_exposure,))

    changed = tuple(
        candidate_root.stage
        for baseline_root, candidate_root in zip(
            baseline.stage_roots,
            candidate.stage_roots,
            strict=True,
        )
        if baseline_root != candidate_root
    )
    assert changed == (M6RegressionStage.RETRIEVAL,)


def test_opaque_retrieval_config_identity_does_not_fabricate_stage_drift() -> None:
    baseline_exposure = _exposure(config_sha256="c" * 64)
    candidate_exposure = _exposure(config_sha256="d" * 64)
    case, _ = _ready_case(())

    baseline = _snapshot(case, retrieval_exposures=(baseline_exposure,))
    candidate = _snapshot(case, retrieval_exposures=(candidate_exposure,))

    assert candidate.stage_roots == baseline.stage_roots


def test_degraded_retrieval_reason_change_moves_only_retrieval_stage() -> None:
    case, _ = _ready_case(())
    provider_unavailable = M6ResolvedRetrievalCycle(
        cycle_index=1,
        degraded_receipt=_degraded_receipt(
            case,
            HearingPrecedentDegradedReason.EMBEDDING_PROVIDER_UNAVAILABLE,
        ),
    )
    index_unavailable = M6ResolvedRetrievalCycle(
        cycle_index=1,
        degraded_receipt=_degraded_receipt(
            case,
            HearingPrecedentDegradedReason.PRECEDENT_INDEX_UNAVAILABLE,
        ),
    )

    baseline = _snapshot(case, retrieval_cycles=(provider_unavailable,))
    candidate = _snapshot(case, retrieval_cycles=(index_unavailable,))

    changed = tuple(
        candidate_root.stage
        for baseline_root, candidate_root in zip(
            baseline.stage_roots,
            candidate.stage_roots,
            strict=True,
        )
        if baseline_root != candidate_root
    )
    assert changed == (M6RegressionStage.RETRIEVAL,)


def test_verdict_precedent_application_change_reaches_exact_gate_not_retrieval() -> None:
    exposure = _exposure()
    without_applications, _ = _ready_case(())
    with_applications, _ = _ready_case(_default_applications(exposure))

    baseline = _snapshot(without_applications, retrieval_exposures=(exposure,))
    candidate = _snapshot(with_applications, retrieval_exposures=(exposure,))

    changed = tuple(
        candidate_root.stage
        for baseline_root, candidate_root in zip(
            baseline.stage_roots,
            candidate.stage_roots,
            strict=True,
        )
        if baseline_root != candidate_root
    )
    assert changed == (
        M6RegressionStage.HEARING,
        M6RegressionStage.GATE,
    )


def test_projection_context_rejects_duplicate_retrieval_cycle_authority() -> None:
    case, _ = _ready_case(())
    exposure = _exposure()
    cycles = (
        M6ResolvedRetrievalCycle(cycle_index=1, success_exposure=exposure),
        M6ResolvedRetrievalCycle(cycle_index=1, success_exposure=exposure),
    )
    model_responses = _resolved_model_responses(case)

    with pytest.raises(ValueError, match="stable cycle order"):
        M6VerifiedProjectionContext(
            case=case,
            perception=_resolved_perception(case),
            historical_source_run_id=case.run_id,
            historical_source_case_id=case.case_id,
            historical_source_manifest_id=case.manifest_id,
            model_reference_authority=_model_reference_authority(
                case,
                cycles,
                model_responses,
            ),
            procedural_gate_authority=_gate_authority(case, cycles),
            model_responses=model_responses,
            retrieval_cycles=cycles,
        )


def test_projection_context_rejects_gate_authority_from_another_snapshot() -> None:
    case, _ = _ready_case(())
    exposure = _exposure()
    cycles = (M6ResolvedRetrievalCycle(cycle_index=1, success_exposure=exposure),)
    model_responses = _resolved_model_responses(case)
    gate_authority = _gate_authority(case, cycles)

    with pytest.raises(ValueError, match="Gate authority differs"):
        M6VerifiedProjectionContext(
            case=case,
            perception=_resolved_perception(case),
            historical_source_run_id=case.run_id,
            historical_source_case_id=case.case_id,
            historical_source_manifest_id=case.manifest_id,
            model_reference_authority=_model_reference_authority(
                case,
                cycles,
                model_responses,
            ),
            procedural_gate_authority=replace(
                gate_authority,
                source_identity_sha256="0" * 64,
            ),
            model_responses=model_responses,
            retrieval_cycles=cycles,
        )


def test_projection_context_rejects_gate_precedents_omitted_from_terminal_cycle() -> None:
    exposure = _exposure()
    case, _ = _ready_case(_default_applications(exposure))
    cycles = (M6ResolvedRetrievalCycle(cycle_index=1, success_exposure=exposure),)
    model_responses = _resolved_model_responses(case)
    gate_authority = _gate_authority(case, cycles)
    assert gate_authority.inputs
    assert all(item.precedent_resolutions for item in gate_authority.inputs)
    forged_gate_authority = replace(
        gate_authority,
        inputs=tuple(replace(item, precedent_resolutions=()) for item in gate_authority.inputs),
    )

    with pytest.raises(ValueError, match="Gate precedent authority differs"):
        M6VerifiedProjectionContext(
            case=case,
            perception=_resolved_perception(case),
            historical_source_run_id=case.run_id,
            historical_source_case_id=case.case_id,
            historical_source_manifest_id=case.manifest_id,
            model_reference_authority=_model_reference_authority(
                case,
                cycles,
                model_responses,
            ),
            procedural_gate_authority=forged_gate_authority,
            model_responses=model_responses,
            retrieval_cycles=cycles,
        )


def test_projection_context_rejects_retrieval_from_another_historical_scope() -> None:
    case, _ = _ready_case(())
    exposure = _exposure()
    cycles = (M6ResolvedRetrievalCycle(cycle_index=1, success_exposure=exposure),)
    model_responses = _resolved_model_responses(case)

    with pytest.raises(ValueError, match="historical source scope"):
        M6VerifiedProjectionContext(
            case=case,
            perception=_resolved_perception(case),
            historical_source_run_id="foreign-run",
            historical_source_case_id=case.case_id,
            historical_source_manifest_id=case.manifest_id,
            model_reference_authority=_model_reference_authority(
                case,
                cycles,
                model_responses,
            ),
            procedural_gate_authority=_gate_authority(case, cycles),
            model_responses=model_responses,
            retrieval_cycles=cycles,
        )


def test_retrieval_projection_fails_closed_when_pack_is_not_in_case_graph() -> None:
    exposure = _exposure()
    unrelated_case = _case(
        run_id=exposure.run_id,
        manifest_id=exposure.manifest_id,
    )

    with pytest.raises(ValueError, match="exact EvidencePack"):
        _snapshot(unrelated_case, retrieval_exposures=(exposure,))


def test_projection_fails_closed_when_safety_signal_authority_is_absent() -> None:
    case = _case()
    fact = case.event.objective_facts[0].model_copy(
        update={
            "source_ref": ArtifactRef(
                kind=ArtifactKind.SAFETY_SIGNAL,
                artifact_id="unresolved-safety-signal",
            )
        }
    )
    event = case.event.model_copy(update={"objective_facts": (fact,)})
    unresolved_case = case.model_copy(update={"event": event})

    with pytest.raises(
        ValueError,
        match="cannot resolve a SAFETY_SIGNAL reference",
    ):
        _snapshot(unresolved_case)
