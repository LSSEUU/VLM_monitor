from __future__ import annotations

from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.config import (
    AlertConfig,
    NumericToleranceConfig,
    ProceduralGateConfig,
)
from labcourt.contracts.detections import Keypoint
from labcourt.contracts.enums import (
    AcquisitionAction,
    AlertLevel,
    AnchorType,
    ArgumentStance,
    ArtifactKind,
    AssociationMethod,
    CropSource,
    JudgeDisposition,
    MediaAccess,
    MediaAvailability,
    MediaType,
    ObjectiveFactKind,
    ObservationSource,
    PpeType,
    PrecedentApplicationMode,
    PrecedentLookupStatus,
    PrecedentSource,
    PrecedentStatus,
    PrivacyPolicy,
    PrivacyReasonCode,
    ProceduralDefectCode,
    RiskLevel,
    UnknownReferenceNamespace,
    UnknownReferenceSource,
    VerdictDecision,
    ViolationType,
    WearStatus,
)
from labcourt.contracts.events import CandidateEvent, ObjectiveFact, derive_case_id
from labcourt.contracts.evidence import (
    Crop,
    EvidencePack,
    EvidencePackDraft,
    ObservabilityComponents,
    ObservabilityScore,
    ObservationSufficiencyInput,
    PrivacyReceipt,
    TrackSummary,
)
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.m3_models import (
    EvidenceCitation,
    PrecedentLookupQuery,
    PrecedentResolution,
    UnknownReferenceAttempt,
)
from labcourt.contracts.precedents import Precedent
from labcourt.contracts.storage import ArtifactRef, ClosureReport
from labcourt.contracts.verdicts import (
    DEFECT_ORDER,
    AcquisitionLogEntry,
    Argument,
    JudgeResponse,
    ObjectiveClaim,
    ObservationLabel,
    ObservationSufficiency,
    PrecedentApplication,
    ProceduralReview,
    Verdict,
)
from labcourt.domain.procedural_gate import (
    ArtifactBounds,
    ProceduralGateAuthorityError,
    ProceduralGateInput,
    review_verdict,
)

FIXTURES = Path(__file__).parents[1] / "fixtures" / "m2"
RUN_ID = "run-01"
SHA_0 = "0" * 64
SHA_1 = "1" * 64
SHA_2 = "2" * 64
SHA_3 = "3" * 64
SHA_4 = "4" * 64
SHA_5 = "5" * 64
SHA_6 = "6" * 64
SHA_7 = "7" * 64
SHA_8 = "8" * 64
SHA_9 = "9" * 64
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64


def _close_pack(draft: EvidencePackDraft) -> EvidencePack:
    report = ClosureReport(
        run_id=draft.run_id,
        root_ref=ArtifactRef(kind=ArtifactKind.CASE, artifact_id=draft.case_id),
        manifest_id=draft.manifest_id,
        input_sha256=draft.closure_input_sha256,
        checked_refs=draft.expected_closure_refs(),
    )
    payload = draft.model_dump(mode="json", exclude={"pack_id"})
    payload["closure_report"] = report.model_dump(mode="json")
    return EvidencePack.model_validate(payload)


def _presence_pack(
    extra_facts: tuple[ObjectiveFact, ...] = (),
) -> EvidencePack:
    event = CandidateEvent.model_validate_json(
        (FIXTURES / "candidate-event-presence.json").read_text(encoding="utf-8")
    )
    frame_ref = ArtifactRef(
        kind=ArtifactKind.FRAME,
        artifact_id="cam-01:demo-ntsc:90",
    )
    source_refs = tuple(
        sorted(
            (
                ArtifactRef(
                    kind=ArtifactKind.DETECTION,
                    artifact_id="det-bottle-090",
                ),
                frame_ref,
            ),
            key=lambda ref: ref.sort_key,
        )
    )
    crop = Crop(
        frame_id=frame_ref.artifact_id,
        source=CropSource.DETECTION_FOCUS,
        bbox=BBoxXYXY(x1=500, y1=300, x2=620, y2=650),
        source_refs=source_refs,
        local_path="frames/bottle.png",
        availability=MediaAvailability.AVAILABLE,
        source_media_sha256=SHA_A,
        pixel_sha256=SHA_B,
        media_sha256=SHA_C,
        output_width=120,
        output_height=350,
        size_bytes=4_096,
        media_type=MediaType.IMAGE_PNG,
        encoding_version="png-v1",
        privacy_receipt=PrivacyReceipt(
            policy=PrivacyPolicy.FULL_REDACTION,
            transform_version="privacy-v1",
            media_access=MediaAccess.LOCAL_ONLY,
            reason_code=PrivacyReasonCode.POLICY_LOCAL_ONLY,
            input_refs=source_refs,
            fill_rgb=(0, 0, 0),
        ),
        primary_track_ref=event.primary_track_ref,
        tags={"zone_id": event.zone_id},
    )
    facts = tuple(
        sorted(
            (*event.objective_facts, *extra_facts),
            key=lambda fact: fact.fact_id,
        )
    )
    return _close_pack(
        EvidencePackDraft(
            run_id=RUN_ID,
            case_id=derive_case_id(event.event_id),
            version=1,
            event=event,
            key_frame_ids=(frame_ref.artifact_id,),
            focus_crops=(crop,),
            objective_facts=facts,
            track_summary=TrackSummary(
                primary_track_ref=event.primary_track_ref,
                start_frame=0,
                end_frame_exclusive=91,
                observed_frame_count=91,
            ),
            confirmation_record=event.confirmation,
            manifest_id=event.manifest_id,
        )
    )


def _absence_crop(event: CandidateEvent, frame_index: int) -> Crop:
    frame_id = f"{event.camera_id}:{event.stream_id}:{frame_index}"
    frame_ref = ArtifactRef(kind=ArtifactKind.FRAME, artifact_id=frame_id)
    bbox = BBoxXYXY(x1=0, y1=0, x2=100, y2=100)
    preserved = BBoxXYXY(x1=10, y1=10, x2=90, y2=55)
    return Crop(
        frame_id=frame_id,
        source=CropSource.ANCHOR_FOCUS,
        bbox=bbox,
        source_refs=(frame_ref,),
        local_path=f"frames/absence-{frame_index}.png",
        availability=MediaAvailability.AVAILABLE,
        source_media_sha256=sha256_hex(["source", frame_id]),
        pixel_sha256=sha256_hex(["pixel", frame_id]),
        media_sha256=sha256_hex(["media", frame_id]),
        output_width=100,
        output_height=100,
        size_bytes=1_024,
        media_type=MediaType.IMAGE_PNG,
        encoding_version="png-v1",
        privacy_receipt=PrivacyReceipt(
            policy=PrivacyPolicy.PPE_PRESERVING_REDACTION,
            transform_version="privacy-v1",
            media_access=MediaAccess.LOCAL_ONLY,
            reason_code=PrivacyReasonCode.PPE_REGION_PRESERVED,
            input_refs=(frame_ref,),
            ppe_type=PpeType.GOGGLES,
            anchor_type=AnchorType.HEAD,
            preserved_regions=(preserved,),
            keypoints=(Keypoint(name="nose", x=50.0, y=40.0, score=0.9),),
            anchor_bbox=preserved,
            association_method=AssociationMethod.KEYPOINT,
            fill_rgb=(0, 0, 0),
        ),
        observability=ObservabilityScore(
            total=0.9,
            components=ObservabilityComponents(
                person_confidence=0.9,
                keypoint_visibility=0.9,
                frontality=0.9,
                sharpness=0.9,
                exposure=0.9,
                non_occlusion=0.9,
            ),
            source=ObservationSource.PRECOMPUTED_FIXTURE,
        ),
        primary_track_ref=event.primary_track_ref,
        tags={"zone_id": event.zone_id},
    )


def _absence_pack() -> EvidencePack:
    event = CandidateEvent.model_validate_json(
        (FIXTURES / "candidate-event-absence-strict.json").read_text(encoding="utf-8")
    )
    temporal = tuple(_absence_crop(event, index) for index in (0, 75, 149))
    clear_ids = tuple(sorted(crop.crop_id for crop in temporal))
    return _close_pack(
        EvidencePackDraft(
            run_id=RUN_ID,
            case_id=derive_case_id(event.event_id),
            version=1,
            event=event,
            key_frame_ids=tuple(
                f"{event.camera_id}:{event.stream_id}:{index}" for index in (0, 75, 149, 150)
            ),
            temporal_crops=temporal,
            objective_facts=event.objective_facts,
            track_summary=TrackSummary(
                primary_track_ref=event.primary_track_ref,
                start_frame=0,
                end_frame_exclusive=152,
                observed_frame_count=151,
            ),
            confirmation_record=event.confirmation,
            observation_sufficiency_input=ObservationSufficiencyInput(
                clear_crop_ids=clear_ids,
                clear_threshold=0.65,
                required_clear_count=2,
                selected_by_observability=True,
            ),
            manifest_id=event.manifest_id,
        )
    )


def _current_closure(pack: EvidencePack, *, run_id: str | None = None) -> ClosureReport:
    root = ArtifactRef(kind=ArtifactKind.EVIDENCE_PACK, artifact_id=pack.pack_id)
    checked = {ref.sort_key: ref for ref in (*pack.expected_closure_refs(), root)}
    return ClosureReport(
        run_id=run_id or pack.run_id,
        root_ref=root,
        manifest_id=pack.manifest_id,
        input_sha256=pack.closure_input_sha256,
        checked_refs=tuple(checked[key] for key in sorted(checked)),
    )


def _gate_config(
    *,
    duration_tolerance: int = 1,
    person_tolerance: int = 0,
    frame_interval_tolerance: int = 1,
    track_interval_tolerance: int = 1,
    detection_tolerance: float = 0.01,
    observability_tolerance: float = 0.01,
    precedent_min: float = 0.55,
    absence_threshold: float = 0.65,
    absence_count: int = 2,
) -> ProceduralGateConfig:
    return ProceduralGateConfig(
        objective_numeric_tolerance=NumericToleranceConfig(
            duration_frames=duration_tolerance,
            person_count=person_tolerance,
            frame_interval_frames=frame_interval_tolerance,
            track_presence_interval_frames=track_interval_tolerance,
            detection_score=detection_tolerance,
            observability=observability_tolerance,
        ),
        precedent_similarity_min=precedent_min,
        absence_clear_frame_threshold=absence_threshold,
        minimum_absence_clear_frames=absence_count,
    )


def _alert_config() -> AlertConfig:
    return AlertConfig(
        cooldown_seconds=30.0,
        repeat_window_days=7,
        confirmed_min_confidence=0.8,
        insufficient_evidence_max_level=AlertLevel.ADVISORY,
    )


def _primary_crop_ref(pack: EvidencePack) -> ArtifactRef:
    return ArtifactRef(kind=ArtifactKind.CROP, artifact_id=pack.crops[0].crop_id)


def _argument(
    pack: EvidencePack,
    *,
    stance: ArgumentStance,
    claim: str,
) -> Argument:
    return Argument(
        stance=stance,
        claim=claim,
        evidence_refs=(_primary_crop_ref(pack),),
        uncertainty=0.05,
    )


def _verdict(
    pack: EvidencePack,
    *,
    decision: VerdictDecision = VerdictDecision.ESTABLISHED,
    confidence: float = 0.95,
    alert_level: AlertLevel = AlertLevel.CONFIRMED,
    violation_type: ViolationType | None = None,
    citations: tuple[EvidenceCitation, ...] | None = None,
    prosecution: tuple[Argument, ...] | None = None,
    defense: tuple[Argument, ...] = (),
    responses: tuple[JudgeResponse, ...] = (),
    precedents: tuple[PrecedentApplication, ...] = (),
    acquisition: tuple[AcquisitionLogEntry, ...] = (),
    objective_claims: tuple[ObjectiveClaim, ...] = (),
    observation_sufficiency: ObservationSufficiency | None = None,
) -> Verdict:
    crop_ref = _primary_crop_ref(pack)
    default_citations = (
        EvidenceCitation(
            evidence_ref=crop_ref,
            bbox=BBoxXYXY(x1=0, y1=0, x2=10, y2=10),
            coordinate_space="CITED_ARTIFACT_PIXELS",
        ),
    )
    default_prosecution = (
        _argument(
            pack,
            stance=ArgumentStance.PROSECUTION,
            claim="The cited structured observation supports establishment.",
        ),
    )
    return Verdict(
        run_id=pack.run_id,
        case_id=pack.case_id,
        version=1,
        screening_id=SHA_1,
        violation_type=violation_type or pack.event.violation_type,
        evidence_pack_id=pack.pack_id,
        evidence_pack_version=pack.version,
        decision=decision,
        confidence=confidence,
        recommended_alert_level=alert_level,
        rationale_summary="The result preserves typed, auditable evidence.",
        evidence_citations=tuple(
            sorted(
                default_citations if citations is None else citations,
                key=lambda item: item.sort_key,
            )
        ),
        prosecution_arguments=tuple(
            sorted(
                default_prosecution if prosecution is None else prosecution,
                key=lambda item: item.argument_id,
            )
        ),
        defense_arguments=tuple(sorted(defense, key=lambda item: item.argument_id)),
        judge_responses=tuple(sorted(responses, key=lambda item: item.sort_key)),
        precedent_applications=tuple(sorted(precedents, key=lambda item: item.sort_key)),
        acquisition_log=tuple(sorted(acquisition, key=lambda item: item.round_index)),
        objective_claims=tuple(sorted(objective_claims, key=lambda item: item.claim_id)),
        observation_sufficiency=observation_sufficiency,
        model_response_refs=(ArtifactRef(kind=ArtifactKind.MODEL_RESPONSE, artifact_id=SHA_2),),
        manifest_id=pack.manifest_id,
    )


def _review(
    verdict: Verdict,
    pack: EvidencePack,
    *,
    closure: ClosureReport | None = None,
    gate_config: ProceduralGateConfig | None = None,
    unknown: tuple[UnknownReferenceAttempt, ...] = (),
    resolutions: tuple[PrecedentResolution, ...] = (),
    bounds: tuple[ArtifactBounds, ...] = (),
) -> ProceduralReview:
    return review_verdict(
        ProceduralGateInput(
            verdict=verdict,
            evidence_pack=pack,
            current_closure=closure or _current_closure(pack),
            gate_config=gate_config or _gate_config(),
            alert_config=_alert_config(),
            gate_version="procedural-gate-v1",
            unknown_reference_attempts=unknown,
            precedent_resolutions=resolutions,
            artifact_bounds=bounds,
        )
    )


def _defect_codes(review: ProceduralReview) -> tuple[ProceduralDefectCode, ...]:
    return tuple(defect.code for defect in review.defects)


def _precedent_application(
    pack: EvidencePack,
    *,
    mode: PrecedentApplicationMode = PrecedentApplicationMode.FOLLOWED,
    reason: str | None = None,
    fact_refs: tuple[ArtifactRef, ...] = (),
) -> PrecedentApplication:
    del pack
    return PrecedentApplication(
        precedent_ref=ArtifactRef(
            kind=ArtifactKind.PRECEDENT,
            artifact_id="precedent-01",
        ),
        mode=mode,
        similarity_score=0.9,
        distinguishing_reason=reason,
        fact_difference_refs=fact_refs,
    )


def _precedent_resolution(
    pack: EvidencePack,
    verdict: Verdict,
    *,
    status: PrecedentLookupStatus = PrecedentLookupStatus.FOUND,
    direction: VerdictDecision = VerdictDecision.ESTABLISHED,
    similarity: float = 0.9,
    case_id: str | None = None,
) -> PrecedentResolution:
    query = PrecedentLookupQuery(
        run_id=pack.run_id,
        case_id=case_id or pack.case_id,
        precedent_id="precedent-01",
        rule_version=pack.event.rule_version,
        evidence_class=pack.event.evidence_class,
        violation_type=pack.event.violation_type,
        manifest_id=pack.manifest_id,
    )
    if status != PrecedentLookupStatus.FOUND:
        return PrecedentResolution(
            query=query,
            status=status,
            lookup_version="precedent-lookup-v1",
        )
    return PrecedentResolution(
        query=query,
        status=status,
        snapshot=Precedent(
            precedent_id=query.precedent_id,
            situation_text="A controlled active precedent snapshot.",
            decision_direction=direction,
            source=PrecedentSource.PRESET,
            status=PrecedentStatus.ACTIVE,
            evidence_class=query.evidence_class,
            violation_type=query.violation_type,
            rule_version=query.rule_version,
        ),
        authoritative_similarity=similarity,
        lookup_version="precedent-lookup-v1",
    )


PRESENCE_PACK = _presence_pack()
ABSENCE_PACK = _absence_pack()


def test_passing_review_is_idempotent_and_does_not_mutate_inputs() -> None:
    verdict = _verdict(PRESENCE_PACK)
    before_verdict = verdict.model_dump_json()
    before_pack = PRESENCE_PACK.model_dump_json()

    first = _review(verdict, PRESENCE_PACK)
    second = _review(verdict, PRESENCE_PACK)

    assert first == second
    assert first.passed is True
    assert first.defects == ()
    assert verdict.model_dump_json() == before_verdict
    assert PRESENCE_PACK.model_dump_json() == before_pack


@pytest.mark.parametrize(
    "replacement, message",
    [
        ({"run_id": "run-02"}, "out-of-scope verdict"),
        ({"case_id": "case-other"}, "out-of-scope verdict"),
        ({"evidence_pack_id": SHA_9}, "out-of-scope verdict"),
        ({"evidence_pack_version": 2}, "out-of-scope verdict"),
        ({"manifest_id": SHA_9}, "out-of-scope verdict"),
    ],
)
def test_gate_rejects_out_of_scope_verdict_authority(
    replacement: dict[str, object],
    message: str,
) -> None:
    verdict = _verdict(PRESENCE_PACK).model_copy(update=replacement)
    with pytest.raises(ProceduralGateAuthorityError, match=message):
        _review(verdict, PRESENCE_PACK)


def test_gate_rejects_noncurrent_or_failed_closure_and_bad_review_version() -> None:
    verdict = _verdict(PRESENCE_PACK)
    out_of_scope = _current_closure(PRESENCE_PACK, run_id="run-02")
    with pytest.raises(
        ProceduralGateAuthorityError,
        match="exact passing current closure",
    ):
        _review(verdict, PRESENCE_PACK, closure=out_of_scope)

    bad_input = ProceduralGateInput(
        verdict=verdict,
        evidence_pack=PRESENCE_PACK,
        current_closure=_current_closure(PRESENCE_PACK),
        gate_config=_gate_config(),
        alert_config=_alert_config(),
        gate_version="procedural-gate-v1",
        review_version=0,
    )
    with pytest.raises(ProceduralGateAuthorityError, match="positive integer"):
        review_verdict(bad_input)


def test_artifact_bounds_are_typed_stable_and_pack_scoped() -> None:
    crop_ref = _primary_crop_ref(PRESENCE_PACK)
    frame_ref = ArtifactRef(
        kind=ArtifactKind.FRAME,
        artifact_id=PRESENCE_PACK.key_frame_ids[0],
    )
    with pytest.raises(ValueError, match="crop or frame"):
        ArtifactBounds(
            ArtifactRef(kind=ArtifactKind.OBJECTIVE_FACT, artifact_id="fact-01"),
            1,
            1,
        )
    for width, height in ((True, 1), (1, False), (0, 1), (1, 0)):
        with pytest.raises(ValueError, match="positive integers"):
            ArtifactBounds(crop_ref, width, height)  # type: ignore[arg-type]

    verdict = _verdict(PRESENCE_PACK)
    reversed_bounds = (
        ArtifactBounds(frame_ref, 1_920, 1_080),
        ArtifactBounds(crop_ref, 120, 350),
    )
    with pytest.raises(ProceduralGateAuthorityError, match="stable order"):
        _review(verdict, PRESENCE_PACK, bounds=reversed_bounds)
    with pytest.raises(ProceduralGateAuthorityError, match="stable order"):
        _review(
            verdict,
            PRESENCE_PACK,
            bounds=(
                ArtifactBounds(crop_ref, 120, 350),
                ArtifactBounds(crop_ref, 120, 350),
            ),
        )
    with pytest.raises(
        ProceduralGateAuthorityError,
        match="outside the current pack",
    ):
        _review(
            verdict,
            PRESENCE_PACK,
            bounds=(
                ArtifactBounds(
                    ArtifactRef(
                        kind=ArtifactKind.FRAME,
                        artifact_id="cam-other:stream:0",
                    ),
                    100,
                    100,
                ),
            ),
        )
    with pytest.raises(ProceduralGateAuthorityError, match="conflict"):
        _review(
            verdict,
            PRESENCE_PACK,
            bounds=(ArtifactBounds(crop_ref, 119, 350),),
        )
    assert _review(
        verdict,
        PRESENCE_PACK,
        bounds=tuple(
            sorted(
                (
                    ArtifactBounds(crop_ref, 120, 350),
                    ArtifactBounds(frame_ref, 1_920, 1_080),
                ),
                key=lambda item: item.sort_key,
            )
        ),
    ).passed


@settings(max_examples=35, deadline=None)
@given(st.sets(st.integers(min_value=20, max_value=40), max_size=8))
def test_fabricated_typed_reference_set_is_complete_and_stable(
    foreign_values: set[int],
) -> None:
    citations = tuple(
        EvidenceCitation(
            evidence_ref=ArtifactRef(
                kind=ArtifactKind.CROP,
                artifact_id=f"{value:064x}",
            )
        )
        for value in sorted(foreign_values)
    )
    verdict = _verdict(PRESENCE_PACK, citations=citations)
    review = _review(verdict, PRESENCE_PACK)
    fabricated = tuple(
        defect
        for defect in review.defects
        if defect.code == ProceduralDefectCode.FABRICATED_EVIDENCE_REFERENCE
    )
    assert len(fabricated) == len(foreign_values)
    assert tuple(defect.sort_key for defect in fabricated) == tuple(
        sorted(defect.sort_key for defect in fabricated)
    )
    assert ProceduralDefectCode.INVALID_COORDINATES not in _defect_codes(review)


def test_unknown_reference_attempts_are_hashed_defects_in_both_namespaces() -> None:
    attempts = (
        UnknownReferenceAttempt(
            namespace=UnknownReferenceNamespace.EVIDENCE,
            source=UnknownReferenceSource.EVIDENCE_CITATION_REF,
            value_sha256=SHA_7,
        ),
        UnknownReferenceAttempt(
            namespace=UnknownReferenceNamespace.PRECEDENT,
            source=UnknownReferenceSource.PRECEDENT_APPLICATION_ID,
            value_sha256=SHA_8,
        ),
    )
    review = _review(_verdict(PRESENCE_PACK), PRESENCE_PACK, unknown=attempts)
    assert _defect_codes(review) == (
        ProceduralDefectCode.FABRICATED_EVIDENCE_REFERENCE,
        ProceduralDefectCode.FABRICATED_PRECEDENT_REFERENCE,
    )
    assert tuple(defect.value_sha256 for defect in review.defects) == (SHA_7, SHA_8)


def test_parser_attempt_and_preserved_typed_reference_collapse_to_one_defect() -> None:
    foreign_ref = ArtifactRef(kind=ArtifactKind.CROP, artifact_id=SHA_7)
    citation = EvidenceCitation(evidence_ref=foreign_ref)
    value_sha256 = sha256_hex(
        [
            "unknown-model-reference",
            1,
            UnknownReferenceNamespace.EVIDENCE.value,
            UnknownReferenceSource.EVIDENCE_CITATION_REF.value,
            foreign_ref.model_dump(mode="json"),
        ]
    )
    attempt = UnknownReferenceAttempt(
        namespace=UnknownReferenceNamespace.EVIDENCE,
        source=UnknownReferenceSource.EVIDENCE_CITATION_REF,
        value_sha256=value_sha256,
    )
    review = _review(
        _verdict(PRESENCE_PACK, citations=(citation,)),
        PRESENCE_PACK,
        unknown=(attempt,),
    )
    assert _defect_codes(review) == (ProceduralDefectCode.FABRICATED_EVIDENCE_REFERENCE,)
    assert review.defects[0].value_sha256 == value_sha256


def test_every_nested_evidence_namespace_is_checked() -> None:
    foreign_crop = ArtifactRef(kind=ArtifactKind.CROP, artifact_id=SHA_7)
    foreign_fact = ArtifactRef(
        kind=ArtifactKind.OBJECTIVE_FACT,
        artifact_id="foreign-fact",
    )
    foreign_tool = ArtifactRef(kind=ArtifactKind.TOOL_RESULT, artifact_id="foreign-tool")
    defense = _argument(
        PRESENCE_PACK,
        stance=ArgumentStance.DEFENSE,
        claim="A defense claim with an allowed primary citation.",
    )
    response = JudgeResponse(
        defense_argument_id=defense.argument_id,
        disposition=JudgeDisposition.REJECTED,
        response_summary="The response cites a foreign typed reference.",
        evidence_refs=(foreign_crop,),
    )
    application = _precedent_application(
        PRESENCE_PACK,
        mode=PrecedentApplicationMode.DISTINGUISHED,
        reason="The objective fact differs.",
        fact_refs=(foreign_fact,),
    )
    no_result = AcquisitionLogEntry(
        round_index=1,
        action=AcquisitionAction.REQUEST_MORE_FRAMES,
        request_ref=ArtifactRef(kind=ArtifactKind.MODEL_REQUEST, artifact_id=SHA_3),
        outcome_summary="The request returned no new typed tool result.",
    )
    acquisition = AcquisitionLogEntry(
        round_index=2,
        action=AcquisitionAction.REDETECT_HIGH_RES,
        request_ref=ArtifactRef(kind=ArtifactKind.MODEL_REQUEST, artifact_id=SHA_4),
        tool_result_ref=foreign_tool,
        outcome_summary="A typed tool result was returned.",
    )
    claim = ObjectiveClaim(
        kind=ObjectiveFactKind.DURATION_FRAMES,
        value=91,
        evidence_ref=foreign_fact,
    )
    observation = ObservationSufficiency(
        clear_threshold=0.65,
        required_clear_count=1,
        observations=(ObservationLabel(crop_id=SHA_6, wear_status=WearStatus.NOT_WORN),),
    )
    verdict = _verdict(
        PRESENCE_PACK,
        defense=(defense,),
        responses=(response,),
        precedents=(application,),
        acquisition=(no_result, acquisition),
        objective_claims=(claim,),
        observation_sufficiency=observation,
    )
    review = _review(verdict, PRESENCE_PACK)
    assert (
        sum(
            defect.code == ProceduralDefectCode.FABRICATED_EVIDENCE_REFERENCE
            for defect in review.defects
        )
        == 5
    )


def test_coordinates_use_cited_artifact_local_bounds_and_fail_closed_without_bounds() -> None:
    crop_ref = _primary_crop_ref(PRESENCE_PACK)
    invalid_crop = EvidenceCitation(
        evidence_ref=crop_ref,
        bbox=BBoxXYXY(x1=0, y1=0, x2=121, y2=10),
        coordinate_space="CITED_ARTIFACT_PIXELS",
    )
    review = _review(
        _verdict(PRESENCE_PACK, citations=(invalid_crop,)),
        PRESENCE_PACK,
    )
    assert _defect_codes(review) == (ProceduralDefectCode.INVALID_COORDINATES,)

    frame_ref = ArtifactRef(
        kind=ArtifactKind.FRAME,
        artifact_id=PRESENCE_PACK.key_frame_ids[0],
    )
    frame_citation = EvidenceCitation(
        evidence_ref=frame_ref,
        bbox=BBoxXYXY(x1=0, y1=0, x2=1_000, y2=700),
        coordinate_space="CITED_ARTIFACT_PIXELS",
    )
    no_bounds = _review(
        _verdict(PRESENCE_PACK, citations=(frame_citation,)),
        PRESENCE_PACK,
    )
    assert _defect_codes(no_bounds) == (ProceduralDefectCode.INVALID_COORDINATES,)
    with_bounds = _review(
        _verdict(PRESENCE_PACK, citations=(frame_citation,)),
        PRESENCE_PACK,
        bounds=(ArtifactBounds(frame_ref, 1_920, 1_080),),
    )
    assert with_bounds.passed


@pytest.mark.parametrize(
    ("resolution_kind", "expected"),
    [
        ("missing", ProceduralDefectCode.FABRICATED_PRECEDENT_REFERENCE),
        ("wrong-scope", ProceduralDefectCode.FABRICATED_PRECEDENT_REFERENCE),
        ("not-visible", ProceduralDefectCode.FABRICATED_PRECEDENT_REFERENCE),
        ("low-score", ProceduralDefectCode.FABRICATED_PRECEDENT_REFERENCE),
        ("duplicate", ProceduralDefectCode.FABRICATED_PRECEDENT_REFERENCE),
        ("direction", ProceduralDefectCode.PRECEDENT_DIRECTION_MISMATCH),
        ("valid", None),
    ],
)
def test_precedent_lookup_and_direction_are_authoritative(
    resolution_kind: str,
    expected: ProceduralDefectCode | None,
) -> None:
    application = _precedent_application(PRESENCE_PACK)
    verdict = _verdict(PRESENCE_PACK, precedents=(application,))
    valid = _precedent_resolution(PRESENCE_PACK, verdict)
    if resolution_kind == "missing":
        resolutions: tuple[PrecedentResolution, ...] = ()
    elif resolution_kind == "wrong-scope":
        resolutions = (
            _precedent_resolution(
                PRESENCE_PACK,
                verdict,
                case_id="case-other",
            ),
        )
    elif resolution_kind == "not-visible":
        resolutions = (
            _precedent_resolution(
                PRESENCE_PACK,
                verdict,
                status=PrecedentLookupStatus.NOT_VISIBLE,
            ),
        )
    elif resolution_kind == "low-score":
        resolutions = (_precedent_resolution(PRESENCE_PACK, verdict, similarity=0.54),)
    elif resolution_kind == "duplicate":
        resolutions = (valid, valid)
    elif resolution_kind == "direction":
        resolutions = (
            _precedent_resolution(
                PRESENCE_PACK,
                verdict,
                direction=VerdictDecision.NOT_ESTABLISHED,
            ),
        )
    else:
        resolutions = (valid,)
    review = _review(
        verdict,
        PRESENCE_PACK,
        resolutions=resolutions,
    )
    assert (expected is None and review.passed) or _defect_codes(review) == (expected,)


@pytest.mark.parametrize(
    ("status", "similarity", "expected_defect"),
    [
        (PrecedentLookupStatus.FOUND, 0.9, True),
        (PrecedentLookupStatus.FOUND, 0.55, True),
        (PrecedentLookupStatus.FOUND, 0.54, False),
        (PrecedentLookupStatus.NOT_VISIBLE, 0.9, False),
    ],
)
def test_every_visible_precedent_above_threshold_requires_an_application(
    status: PrecedentLookupStatus,
    similarity: float,
    expected_defect: bool,
) -> None:
    verdict = _verdict(PRESENCE_PACK)
    resolution = _precedent_resolution(
        PRESENCE_PACK,
        verdict,
        status=status,
        similarity=similarity,
    )

    review = _review(verdict, PRESENCE_PACK, resolutions=(resolution,))

    assert (
        ProceduralDefectCode.EMPTY_DISTINGUISHING_REASON in _defect_codes(review)
    ) is expected_defect


@pytest.mark.parametrize(
    ("reason", "fact_refs", "expected_defect"),
    [
        (None, (), True),
        ("The duration differs.", (), True),
        (
            None,
            (ArtifactRef(kind=ArtifactKind.OBJECTIVE_FACT, artifact_id="fact-duration-presence"),),
            True,
        ),
        (
            "The authoritative duration differs.",
            (
                ArtifactRef(
                    kind=ArtifactKind.OBJECTIVE_FACT,
                    artifact_id="fact-duration-presence",
                ),
            ),
            False,
        ),
    ],
)
def test_distinguished_precedent_requires_reason_and_fact_reference(
    reason: str | None,
    fact_refs: tuple[ArtifactRef, ...],
    expected_defect: bool,
) -> None:
    application = _precedent_application(
        PRESENCE_PACK,
        mode=PrecedentApplicationMode.DISTINGUISHED,
        reason=reason,
        fact_refs=fact_refs,
    )
    verdict = _verdict(PRESENCE_PACK, precedents=(application,))
    resolution = _precedent_resolution(PRESENCE_PACK, verdict)
    review = _review(verdict, PRESENCE_PACK, resolutions=(resolution,))
    assert (
        ProceduralDefectCode.EMPTY_DISTINGUISHING_REASON in _defect_codes(review)
    ) is expected_defect


@pytest.mark.parametrize(
    ("citations", "prosecution"),
    [
        ((), None),
        (None, ()),
        ((), ()),
    ],
)
def test_established_verdict_requires_evidence_and_prosecution(
    citations: tuple[EvidenceCitation, ...] | None,
    prosecution: tuple[Argument, ...] | None,
) -> None:
    verdict = _verdict(
        PRESENCE_PACK,
        citations=citations,
        prosecution=prosecution,
    )
    review = _review(verdict, PRESENCE_PACK)
    assert ProceduralDefectCode.ESTABLISHED_WITHOUT_EVIDENCE in _defect_codes(review)

    not_established = _verdict(
        PRESENCE_PACK,
        decision=VerdictDecision.NOT_ESTABLISHED,
        citations=(),
        prosecution=(),
        alert_level=AlertLevel.ADVISORY,
    )
    assert _review(not_established, PRESENCE_PACK).passed


@settings(max_examples=45, deadline=None)
@given(
    response_counts=st.lists(
        st.integers(min_value=0, max_value=2),
        min_size=0,
        max_size=6,
    ),
    foreign_response_count=st.integers(min_value=0, max_value=2),
)
def test_every_defense_point_has_exactly_one_response(
    response_counts: list[int],
    foreign_response_count: int,
) -> None:
    defenses = tuple(
        _argument(
            PRESENCE_PACK,
            stance=ArgumentStance.DEFENSE,
            claim=f"Defense point {index} requires an exact response.",
        )
        for index in range(len(response_counts))
    )
    responses = tuple(
        JudgeResponse(
            defense_argument_id=argument.argument_id,
            disposition=JudgeDisposition.REJECTED,
            response_summary=f"Response {response_index} to defense point {index}.",
            evidence_refs=(_primary_crop_ref(PRESENCE_PACK),),
        )
        for index, (argument, count) in enumerate(zip(defenses, response_counts, strict=True))
        for response_index in range(count)
    )
    foreign_responses = tuple(
        JudgeResponse(
            defense_argument_id=SHA_9,
            disposition=JudgeDisposition.REJECTED,
            response_summary=f"Response {index} to a defense point outside the verdict.",
            evidence_refs=(_primary_crop_ref(PRESENCE_PACK),),
        )
        for index in range(foreign_response_count)
    )
    verdict = _verdict(
        PRESENCE_PACK,
        defense=defenses,
        responses=(*responses, *foreign_responses),
    )
    review = _review(verdict, PRESENCE_PACK)
    has_defect = ProceduralDefectCode.UNANSWERED_DEFENSE_POINT in _defect_codes(review)
    expected_exact_bijection = all(count == 1 for count in response_counts) and not (
        foreign_response_count
    )
    assert has_defect is (not expected_exact_bijection)


@pytest.mark.parametrize(
    ("decision", "confidence", "level", "expected"),
    [
        (
            VerdictDecision.INSUFFICIENT_EVIDENCE,
            0.95,
            AlertLevel.CONFIRMED,
            True,
        ),
        (
            VerdictDecision.INSUFFICIENT_EVIDENCE,
            0.95,
            AlertLevel.EMERGENCY,
            True,
        ),
        (
            VerdictDecision.INSUFFICIENT_EVIDENCE,
            0.1,
            AlertLevel.ADVISORY,
            False,
        ),
        (VerdictDecision.ESTABLISHED, 0.79, AlertLevel.CONFIRMED, True),
        (VerdictDecision.ESTABLISHED, 0.79, AlertLevel.EMERGENCY, True),
        (VerdictDecision.ESTABLISHED, 0.8, AlertLevel.CONFIRMED, False),
        (VerdictDecision.ESTABLISHED, 0.1, AlertLevel.ADVISORY, False),
    ],
)
def test_confidence_and_insufficient_alert_policy(
    decision: VerdictDecision,
    confidence: float,
    level: AlertLevel,
    expected: bool,
) -> None:
    review = _review(
        _verdict(
            PRESENCE_PACK,
            decision=decision,
            confidence=confidence,
            alert_level=level,
        ),
        PRESENCE_PACK,
    )
    has_defect = ProceduralDefectCode.CONFIDENCE_ALERT_LEVEL_MISMATCH in _defect_codes(review)
    assert has_defect is expected


@settings(max_examples=45, deadline=None)
@given(
    kind=st.sampled_from((ObjectiveFactKind.DURATION_FRAMES, ObjectiveFactKind.PERSON_COUNT)),
    authoritative=st.integers(min_value=10, max_value=500),
    tolerance=st.integers(min_value=0, max_value=5),
    delta=st.integers(min_value=-8, max_value=8),
)
def test_integer_objective_claims_use_inclusive_configured_tolerance(
    kind: ObjectiveFactKind,
    authoritative: int,
    tolerance: int,
    delta: int,
) -> None:
    fact = _extra_objective_fact(kind, authoritative)
    pack = _presence_pack((fact,))
    claim = ObjectiveClaim(
        kind=kind,
        value=authoritative + delta,
        evidence_ref=ArtifactRef(
            kind=ArtifactKind.OBJECTIVE_FACT,
            artifact_id=fact.fact_id,
        ),
    )
    config = (
        _gate_config(duration_tolerance=tolerance)
        if kind == ObjectiveFactKind.DURATION_FRAMES
        else _gate_config(person_tolerance=tolerance)
    )
    review = _review(
        _verdict(pack, objective_claims=(claim,)),
        pack,
        gate_config=config,
    )
    contradicted = ProceduralDefectCode.OBJECTIVE_ASSERTION_CONTRADICTION in _defect_codes(review)
    assert contradicted is (abs(delta) > tolerance)


def _extra_objective_fact(
    kind: ObjectiveFactKind,
    value: object,
) -> ObjectiveFact:
    authority = PRESENCE_PACK.objective_facts[0]
    return ObjectiveFact(
        fact_id=f"fact-extra-{kind.value.lower().replace('_', '-')}",
        kind=kind,
        value=value,  # type: ignore[arg-type]
        source_ref=authority.source_ref,
        source_manifest_id=authority.source_manifest_id,
        unit=None,
    )


@settings(max_examples=45, deadline=None)
@given(
    kind=st.sampled_from(
        (
            ObjectiveFactKind.FRAME_INTERVAL,
            ObjectiveFactKind.TRACK_PRESENCE_INTERVAL,
        )
    ),
    start=st.integers(min_value=20, max_value=200),
    length=st.integers(min_value=20, max_value=200),
    tolerance=st.integers(min_value=0, max_value=5),
    start_delta=st.integers(min_value=-8, max_value=8),
    end_delta=st.integers(min_value=-8, max_value=8),
)
def test_interval_objective_claims_compare_both_endpoints_with_inclusive_tolerance(
    kind: ObjectiveFactKind,
    start: int,
    length: int,
    tolerance: int,
    start_delta: int,
    end_delta: int,
) -> None:
    authoritative = (start, start + length)
    claimed = (start + start_delta, start + length + end_delta)
    fact = _extra_objective_fact(kind, authoritative)
    pack = _presence_pack((fact,))
    claim = ObjectiveClaim(
        kind=kind,
        value=claimed,
        evidence_ref=ArtifactRef(
            kind=ArtifactKind.OBJECTIVE_FACT,
            artifact_id=fact.fact_id,
        ),
    )
    config = (
        _gate_config(frame_interval_tolerance=tolerance)
        if kind == ObjectiveFactKind.FRAME_INTERVAL
        else _gate_config(track_interval_tolerance=tolerance)
    )

    review = _review(
        _verdict(pack, objective_claims=(claim,)),
        pack,
        gate_config=config,
    )

    contradicted = ProceduralDefectCode.OBJECTIVE_ASSERTION_CONTRADICTION in _defect_codes(review)
    assert contradicted is (abs(start_delta) > tolerance or abs(end_delta) > tolerance)


@settings(max_examples=45, deadline=None)
@given(
    kind=st.sampled_from((ObjectiveFactKind.DETECTION_SCORE, ObjectiveFactKind.OBSERVABILITY)),
    authoritative_step=st.integers(min_value=200, max_value=800),
    tolerance_step=st.integers(min_value=0, max_value=50),
    delta_step=st.integers(min_value=-100, max_value=100),
)
def test_decimal_objective_claims_use_exact_inclusive_decimal_tolerance(
    kind: ObjectiveFactKind,
    authoritative_step: int,
    tolerance_step: int,
    delta_step: int,
) -> None:
    authoritative = authoritative_step / 1_000
    claimed = (authoritative_step + delta_step) / 1_000
    tolerance = tolerance_step / 1_000
    fact = _extra_objective_fact(kind, authoritative)
    pack = _presence_pack((fact,))
    claim = ObjectiveClaim(
        kind=kind,
        value=claimed,
        evidence_ref=ArtifactRef(
            kind=ArtifactKind.OBJECTIVE_FACT,
            artifact_id=fact.fact_id,
        ),
    )
    config = (
        _gate_config(detection_tolerance=tolerance)
        if kind == ObjectiveFactKind.DETECTION_SCORE
        else _gate_config(observability_tolerance=tolerance)
    )

    review = _review(
        _verdict(pack, objective_claims=(claim,)),
        pack,
        gate_config=config,
    )

    contradicted = ProceduralDefectCode.OBJECTIVE_ASSERTION_CONTRADICTION in _defect_codes(review)
    assert contradicted is (abs(delta_step) > tolerance_step)


@pytest.mark.parametrize(
    ("kind", "authoritative", "within", "outside"),
    [
        (ObjectiveFactKind.PERSON_COUNT, 2, 2, 3),
        (ObjectiveFactKind.ZONE_ID, "hood-01", "hood-01", "hood-02"),
        (ObjectiveFactKind.RISK_LEVEL, RiskLevel.HIGH, RiskLevel.HIGH, RiskLevel.LOW),
        (ObjectiveFactKind.FRAME_INTERVAL, (10, 20), (9, 21), (8, 20)),
        (
            ObjectiveFactKind.TRACK_PRESENCE_INTERVAL,
            (10, 20),
            (11, 19),
            (10, 22),
        ),
        (ObjectiveFactKind.DETECTION_SCORE, 0.8, 0.81, 0.811),
        (ObjectiveFactKind.OBSERVABILITY, 0.9, 0.89, 0.889),
    ],
)
def test_every_objective_kind_uses_its_exact_or_numeric_policy(
    kind: ObjectiveFactKind,
    authoritative: object,
    within: object,
    outside: object,
) -> None:
    fact = _extra_objective_fact(kind, authoritative)
    pack = _presence_pack((fact,))
    ref = ArtifactRef(kind=ArtifactKind.OBJECTIVE_FACT, artifact_id=fact.fact_id)
    within_claim = ObjectiveClaim(
        kind=kind,
        value=within,  # type: ignore[arg-type]
        evidence_ref=ref,
    )
    outside_claim = ObjectiveClaim(
        kind=kind,
        value=outside,  # type: ignore[arg-type]
        evidence_ref=ref,
    )
    assert _review(
        _verdict(pack, objective_claims=(within_claim,)),
        pack,
    ).passed
    assert _defect_codes(
        _review(
            _verdict(pack, objective_claims=(outside_claim,)),
            pack,
        )
    ) == (ProceduralDefectCode.OBJECTIVE_ASSERTION_CONTRADICTION,)


def test_objective_kind_mismatch_is_rejected_but_unknown_fact_is_not_double_counted() -> None:
    fact = PRESENCE_PACK.objective_facts[0]
    fact_ref = ArtifactRef(
        kind=ArtifactKind.OBJECTIVE_FACT,
        artifact_id=fact.fact_id,
    )
    mismatched = ObjectiveClaim(
        kind=ObjectiveFactKind.PERSON_COUNT,
        value=91,
        evidence_ref=fact_ref,
    )
    unknown = ObjectiveClaim(
        kind=ObjectiveFactKind.PERSON_COUNT,
        value=3,
        evidence_ref=ArtifactRef(
            kind=ArtifactKind.OBJECTIVE_FACT,
            artifact_id="unknown-objective-fact",
        ),
    )
    mismatch_review = _review(
        _verdict(PRESENCE_PACK, objective_claims=(mismatched,)),
        PRESENCE_PACK,
    )
    assert _defect_codes(mismatch_review) == (
        ProceduralDefectCode.OBJECTIVE_ASSERTION_CONTRADICTION,
    )
    unknown_review = _review(
        _verdict(PRESENCE_PACK, objective_claims=(unknown,)),
        PRESENCE_PACK,
    )
    assert _defect_codes(unknown_review) == (ProceduralDefectCode.FABRICATED_EVIDENCE_REFERENCE,)


def test_violation_type_is_checked_against_pack_authority() -> None:
    verdict = _verdict(
        PRESENCE_PACK,
        violation_type=ViolationType.PPE_GOGGLES_MISSING,
    )
    review = _review(verdict, PRESENCE_PACK)
    assert _defect_codes(review) == (ProceduralDefectCode.VIOLATION_TYPE_MISMATCH,)
    assert review.defects[0].related_refs == (
        ArtifactRef(
            kind=ArtifactKind.EVENT,
            artifact_id=PRESENCE_PACK.event.event_id,
        ),
    )


def _absence_observations(
    statuses: tuple[WearStatus | None, ...],
    *,
    threshold: float = 0.65,
    required: int = 2,
) -> ObservationSufficiency:
    clear_ids = ABSENCE_PACK.observation_sufficiency_input.clear_crop_ids
    observations = tuple(
        ObservationLabel(crop_id=crop_id, wear_status=status)
        for crop_id, status in zip(clear_ids, statuses, strict=True)
        if status is not None
    )
    return ObservationSufficiency(
        clear_threshold=threshold,
        required_clear_count=required,
        observations=observations,
    )


@settings(max_examples=45, deadline=None)
@given(
    st.tuples(
        st.one_of(st.none(), st.sampled_from(tuple(WearStatus))),
        st.one_of(st.none(), st.sampled_from(tuple(WearStatus))),
        st.one_of(st.none(), st.sampled_from(tuple(WearStatus))),
    )
)
def test_absence_establishment_requires_every_authoritative_clear_not_worn(
    statuses: tuple[WearStatus | None, WearStatus | None, WearStatus | None],
) -> None:
    verdict = _verdict(
        ABSENCE_PACK,
        observation_sufficiency=_absence_observations(statuses),
    )
    review = _review(verdict, ABSENCE_PACK)
    has_defect = ProceduralDefectCode.ABSENCE_FROM_INSUFFICIENT_OBSERVATION in _defect_codes(review)
    assert has_defect is (statuses != (WearStatus.NOT_WORN,) * 3)


@pytest.mark.parametrize(
    ("observation", "config", "expected"),
    [
        (None, _gate_config(), True),
        (
            _absence_observations((WearStatus.NOT_WORN,) * 3, threshold=0.66),
            _gate_config(),
            True,
        ),
        (
            _absence_observations((WearStatus.NOT_WORN,) * 3, required=3),
            _gate_config(),
            True,
        ),
        (
            _absence_observations((WearStatus.NOT_WORN,) * 3),
            _gate_config(absence_threshold=0.66),
            True,
        ),
        (
            _absence_observations((WearStatus.NOT_WORN,) * 3),
            _gate_config(absence_count=3),
            True,
        ),
        (
            _absence_observations((WearStatus.NOT_WORN,) * 3),
            _gate_config(),
            False,
        ),
    ],
)
def test_absence_threshold_count_and_verdict_authority_must_agree(
    observation: ObservationSufficiency | None,
    config: ProceduralGateConfig,
    expected: bool,
) -> None:
    review = _review(
        _verdict(ABSENCE_PACK, observation_sufficiency=observation),
        ABSENCE_PACK,
        gate_config=config,
    )
    assert (
        ProceduralDefectCode.ABSENCE_FROM_INSUFFICIENT_OBSERVATION in _defect_codes(review)
    ) is expected


def test_absence_gate_does_not_apply_to_presence_or_non_established_outcomes() -> None:
    assert _review(_verdict(PRESENCE_PACK), PRESENCE_PACK).passed
    verdict = _verdict(
        ABSENCE_PACK,
        decision=VerdictDecision.NOT_ESTABLISHED,
        alert_level=AlertLevel.ADVISORY,
        observation_sufficiency=None,
    )
    assert _review(verdict, ABSENCE_PACK).passed


def test_multiple_independent_defects_follow_taxonomy_order() -> None:
    fact = PRESENCE_PACK.objective_facts[0]
    bad_claim = ObjectiveClaim(
        kind=fact.kind,
        value=100,
        evidence_ref=ArtifactRef(
            kind=ArtifactKind.OBJECTIVE_FACT,
            artifact_id=fact.fact_id,
        ),
    )
    verdict = _verdict(
        PRESENCE_PACK,
        confidence=0.1,
        citations=(),
        prosecution=(),
        objective_claims=(bad_claim,),
        violation_type=ViolationType.PPE_GOGGLES_MISSING,
    )
    review = _review(verdict, PRESENCE_PACK)
    ranks = tuple(DEFECT_ORDER.index(code) for code in _defect_codes(review))
    assert ranks == tuple(sorted(ranks))
    assert _defect_codes(review) == (
        ProceduralDefectCode.ESTABLISHED_WITHOUT_EVIDENCE,
        ProceduralDefectCode.CONFIDENCE_ALERT_LEVEL_MISMATCH,
        ProceduralDefectCode.OBJECTIVE_ASSERTION_CONTRADICTION,
        ProceduralDefectCode.VIOLATION_TYPE_MISMATCH,
    )
