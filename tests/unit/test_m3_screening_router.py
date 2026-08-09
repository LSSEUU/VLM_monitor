from __future__ import annotations

from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.detections import Keypoint
from labcourt.contracts.enums import (
    AlertLevel,
    AnchorType,
    ArtifactKind,
    AssociationMethod,
    CropSource,
    EvidenceClass,
    MediaAccess,
    MediaAvailability,
    MediaType,
    ObjectiveFactKind,
    ObservationSource,
    PpeType,
    PrivacyPolicy,
    PrivacyReasonCode,
    ScreeningConflictCode,
    ScreeningDecision,
    VerdictDecision,
    ViolationType,
    WearStatus,
)
from labcourt.contracts.events import CandidateEvent, derive_case_id
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
from labcourt.contracts.m3_models import EvidenceCitation
from labcourt.contracts.screening import (
    FrameObservation,
    ParsedScreeningOutput,
    ScreeningModelPayload,
)
from labcourt.contracts.storage import ArtifactRef, ClosureReport
from labcourt.contracts.verdicts import ObjectiveClaim
from labcourt.domain.screening_router import (
    DETERMINISTIC_NARRATIVE_ROUTER_VERSION,
    FastVerdictBuilder,
    FastVerdictPolicy,
    ScreeningRouteError,
    ScreeningRoutePolicy,
    ScreeningRouter,
    build_fast_verdict,
    route_screening,
)

FIXTURES = Path(__file__).parents[1] / "fixtures" / "m2"
RUN_ID = "run-01"
SHA_1 = "1" * 64
SHA_2 = "2" * 64
SHA_3 = "3" * 64
SHA_4 = "4" * 64
SHA_5 = "5" * 64


def _close_pack(draft: EvidencePackDraft) -> EvidencePack:
    closure = ClosureReport(
        run_id=draft.run_id,
        root_ref=ArtifactRef(kind=ArtifactKind.CASE, artifact_id=draft.case_id),
        manifest_id=draft.manifest_id,
        input_sha256=draft.closure_input_sha256,
        checked_refs=draft.expected_closure_refs(),
    )
    payload = draft.model_dump(mode="json", exclude={"pack_id"})
    payload["closure_report"] = closure.model_dump(mode="json")
    return EvidencePack.model_validate(payload)


def _presence_pack(*, complete: bool = True) -> EvidencePack:
    event = CandidateEvent.model_validate_json(
        (FIXTURES / "candidate-event-presence.json").read_text(encoding="utf-8")
    )
    frame_ref = ArtifactRef(
        kind=ArtifactKind.FRAME,
        artifact_id=f"{event.camera_id}:{event.stream_id}:{event.trigger_frame}",
    )
    detection_ref = ArtifactRef(
        kind=ArtifactKind.DETECTION,
        artifact_id="det-bottle-090",
    )
    source_refs = tuple(sorted((frame_ref, detection_ref), key=lambda ref: ref.sort_key))
    crop = Crop(
        frame_id=frame_ref.artifact_id,
        source=CropSource.DETECTION_FOCUS,
        bbox=BBoxXYXY(x1=500, y1=300, x2=620, y2=650),
        source_refs=source_refs,
        local_path="frames/bottle.png",
        availability=MediaAvailability.AVAILABLE,
        source_media_sha256=SHA_1,
        pixel_sha256=SHA_2,
        media_sha256=SHA_3,
        output_width=120,
        output_height=350,
        size_bytes=4_096,
        media_type=MediaType.IMAGE_PNG,
        encoding_version="png-v1",
        privacy_receipt=PrivacyReceipt(
            policy=PrivacyPolicy.FULL_REDACTION,
            transform_version="full-redaction-v1",
            media_access=MediaAccess.LOCAL_ONLY,
            reason_code=PrivacyReasonCode.POLICY_LOCAL_ONLY,
            input_refs=source_refs,
            fill_rgb=(0, 0, 0),
        ),
        primary_track_ref=event.primary_track_ref,
        tags={"zone_id": event.zone_id},
    )
    return _close_pack(
        EvidencePackDraft(
            run_id=RUN_ID,
            case_id=derive_case_id(event.event_id),
            version=1,
            complete=complete,
            event=event,
            key_frame_ids=(frame_ref.artifact_id,),
            focus_crops=(crop,),
            objective_facts=event.objective_facts,
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


def _absence_crop(event: CandidateEvent, frame_index: int, *, clear: bool) -> Crop:
    frame_id = f"{event.camera_id}:{event.stream_id}:{frame_index}"
    frame_ref = ArtifactRef(kind=ArtifactKind.FRAME, artifact_id=frame_id)
    preserved = BBoxXYXY(x1=10, y1=10, x2=90, y2=55)
    score = 0.9 if clear else 0.2
    return Crop(
        frame_id=frame_id,
        source=CropSource.ANCHOR_FOCUS,
        bbox=BBoxXYXY(x1=0, y1=0, x2=100, y2=100),
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
            transform_version="ppe-preserve-v1",
            media_access=MediaAccess.LOCAL_ONLY,
            reason_code=PrivacyReasonCode.PPE_REGION_PRESERVED,
            input_refs=(frame_ref,),
            ppe_type=PpeType.GOGGLES,
            anchor_type=AnchorType.HEAD,
            preserved_regions=(preserved,),
            keypoints=(Keypoint(name="nose", x=50.0, y=40.0, score=score),),
            anchor_bbox=preserved,
            association_method=AssociationMethod.KEYPOINT,
            fill_rgb=(0, 0, 0),
        ),
        observability=ObservabilityScore(
            total=score,
            components=ObservabilityComponents(
                person_confidence=score,
                keypoint_visibility=score,
                frontality=score,
                sharpness=score,
                exposure=score,
                non_occlusion=score,
            ),
            source=ObservationSource.PRECOMPUTED_FIXTURE,
        ),
        primary_track_ref=event.primary_track_ref,
        tags={"zone_id": event.zone_id},
    )


def _absence_pack(*, include_temporal: bool = True) -> EvidencePack:
    event = CandidateEvent.model_validate_json(
        (FIXTURES / "candidate-event-absence-strict.json").read_text(encoding="utf-8")
    )
    temporal = (
        tuple(
            _absence_crop(event, frame_index, clear=clear)
            for frame_index, clear in ((0, True), (75, True), (100, False), (149, True))
        )
        if include_temporal
        else ()
    )
    observed_scores: list[tuple[str, float]] = []
    for crop in temporal:
        assert crop.observability is not None
        observed_scores.append((crop.crop_id, crop.observability.total))
    clear_ids = tuple(crop_id for crop_id, score in observed_scores if score >= 0.5)
    unclear_ids = tuple(crop_id for crop_id, score in observed_scores if score < 0.5)
    # Deliberately reverse pack authority: the router must canonicalize it.
    authority = ObservationSufficiencyInput(
        clear_crop_ids=tuple(reversed(clear_ids)),
        unclear_crop_ids=tuple(reversed(unclear_ids)),
        clear_threshold=0.5,
        required_clear_count=2,
        selected_by_observability=True,
    )
    key_indexes = (0, 75, 100, 149, 150, 151)
    return _close_pack(
        EvidencePackDraft(
            run_id=RUN_ID,
            case_id=derive_case_id(event.event_id),
            version=1,
            event=event,
            key_frame_ids=tuple(
                f"{event.camera_id}:{event.stream_id}:{index}" for index in key_indexes
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
            observation_sufficiency_input=authority,
            manifest_id=event.manifest_id,
        )
    )


def _absence_authority(pack: EvidencePack) -> ObservationSufficiencyInput:
    authority = pack.observation_sufficiency_input
    assert authority is not None
    return authority


def _citations(pack: EvidencePack) -> tuple[EvidenceCitation, ...]:
    crop = pack.crops[0]
    values = (
        EvidenceCitation(
            evidence_ref=ArtifactRef(kind=ArtifactKind.CROP, artifact_id=crop.crop_id),
        ),
        EvidenceCitation(
            evidence_ref=ArtifactRef(kind=ArtifactKind.CROP, artifact_id=crop.crop_id),
            bbox=BBoxXYXY(x1=1, y1=1, x2=20, y2=20),
            coordinate_space="CITED_ARTIFACT_PIXELS",
        ),
    )
    return tuple(sorted(values, key=lambda citation: citation.sort_key))


def _objective_claim(pack: EvidencePack) -> ObjectiveClaim:
    fact = pack.objective_facts[0]
    return ObjectiveClaim(
        kind=ObjectiveFactKind.DURATION_FRAMES,
        value=fact.value,
        evidence_ref=ArtifactRef(
            kind=ArtifactKind.OBJECTIVE_FACT,
            artifact_id=fact.fact_id,
        ),
    )


def _parsed(
    pack: EvidencePack,
    *,
    probability: float,
    observations: tuple[FrameObservation, ...] = (),
    evidence_class: EvidenceClass | None = None,
    violation_type: ViolationType | None = None,
    citations: tuple[EvidenceCitation, ...] | None = None,
) -> ParsedScreeningOutput:
    payload = ScreeningModelPayload(
        violation_type=violation_type or pack.event.violation_type,
        evidence_class=evidence_class or pack.event.evidence_class,
        violation_probability=probability,
        frame_observations=observations,
        evidence_citations=_citations(pack) if citations is None else citations,
        objective_claims=(_objective_claim(pack),),
        prosecution_summary="The cited structured evidence supports this screening proposal.",
        rationale_summary="The fast route uses only typed model output and pack authority.",
    )
    return ParsedScreeningOutput(
        run_id=pack.run_id,
        case_id=pack.case_id,
        evidence_pack_id=pack.pack_id,
        evidence_pack_version=pack.version,
        request_id=SHA_1,
        response_id=SHA_2,
        response_content_sha256=SHA_3,
        output_schema_sha256=SHA_4,
        payload=payload,
        manifest_id=pack.manifest_id,
    )


def _policy(*, strong: float = 1.0) -> ScreeningRoutePolicy:
    return ScreeningRoutePolicy(
        low_probability=0.2,
        high_probability=0.8,
        strong_signal_threshold=strong,
    )


@given(
    probability=st.floats(
        min_value=0,
        max_value=1,
        allow_nan=False,
        allow_infinity=False,
        width=32,
    )
)
def test_presence_low_high_and_gray_routes_are_total_and_deterministic(
    probability: float,
) -> None:
    pack = _presence_pack()
    parsed = _parsed(pack, probability=probability)

    first = route_screening(parsed, pack, _policy())
    second = ScreeningRouter(_policy()).route(parsed, pack)

    expected = (
        ScreeningDecision.NOT_ESTABLISHED
        if probability <= 0.2
        else (ScreeningDecision.ESTABLISHED if probability >= 0.8 else ScreeningDecision.ESCALATE)
    )
    assert first.decision == expected
    assert first == second
    assert canonical_json(first.model_dump(mode="json")) == canonical_json(
        second.model_dump(mode="json")
    )


@pytest.mark.parametrize(
    ("probability", "l1_is_strong", "expected_conflict"),
    [
        (0.1, True, True),
        (0.5, True, False),
        (0.9, True, False),
        (0.1, False, False),
    ],
)
def test_strong_signal_conflict_is_presence_only_and_requires_negative_route(
    probability: float,
    l1_is_strong: bool,
    expected_conflict: bool,
) -> None:
    pack = _presence_pack()
    threshold = pack.event.l1_score if l1_is_strong else 1.0
    result = route_screening(
        _parsed(pack, probability=probability), pack, _policy(strong=threshold)
    )
    assert (
        ScreeningConflictCode.STRONG_SIGNAL_CONFLICT in result.conflict_codes
    ) is expected_conflict
    if expected_conflict:
        assert result.decision == ScreeningDecision.ESCALATE

    absence = _absence_pack()
    clear_ids = tuple(sorted(_absence_authority(absence).clear_crop_ids))
    worn = _observations(clear_ids, (WearStatus.WORN,) * len(clear_ids))
    absence_result = route_screening(
        _parsed(absence, probability=0.1, observations=worn),
        absence,
        _policy(strong=absence.event.l1_score),
    )
    assert ScreeningConflictCode.STRONG_SIGNAL_CONFLICT not in absence_result.conflict_codes
    assert absence_result.decision == ScreeningDecision.NOT_ESTABLISHED


def _observations(
    crop_ids: tuple[str, ...],
    statuses: tuple[WearStatus, ...],
) -> tuple[FrameObservation, ...]:
    values = tuple(
        FrameObservation(
            crop_id=crop_id,
            wear_status=status,
            reason_summary=f"Typed fixture label: {status.value}.",
        )
        for crop_id, status in zip(crop_ids, statuses, strict=True)
    )
    return tuple(sorted(values, key=lambda observation: observation.sort_key))


@given(
    statuses=st.lists(
        st.sampled_from(tuple(WearStatus)),
        min_size=3,
        max_size=3,
    ).map(tuple)
)
def test_absence_route_votes_only_with_every_authoritative_clear_crop(
    statuses: tuple[WearStatus, ...],
) -> None:
    pack = _absence_pack()
    clear_ids = tuple(sorted(_absence_authority(pack).clear_crop_ids))
    result = route_screening(
        _parsed(pack, probability=0.9, observations=_observations(clear_ids, statuses)),
        pack,
        _policy(),
    )
    if WearStatus.WORN in statuses:
        expected = ScreeningDecision.NOT_ESTABLISHED
    elif all(status == WearStatus.NOT_WORN for status in statuses):
        expected = ScreeningDecision.ESTABLISHED
    else:
        expected = ScreeningDecision.ESCALATE
    assert result.decision == expected
    assert result.authoritative_clear_crop_ids == clear_ids


def test_absence_non_clear_labels_do_not_vote_and_correction_is_context_only() -> None:
    pack = _absence_pack()
    authority = _absence_authority(pack)
    clear_ids = tuple(sorted(authority.clear_crop_ids))
    non_clear_ids = tuple(sorted(authority.unclear_crop_ids))
    observations = _observations(
        (*clear_ids, *non_clear_ids),
        (
            *((WearStatus.NOT_WORN,) * len(clear_ids)),
            *((WearStatus.WORN,) * len(non_clear_ids)),
        ),
    )
    result = route_screening(
        _parsed(pack, probability=0.9, observations=observations),
        pack,
        _policy(),
    )
    assert result.decision == ScreeningDecision.ESTABLISHED
    assert result.alleged_interval_crop_ids == tuple(
        sorted(crop.crop_id for crop in pack.temporal_crops)
    )
    assert result.correction_frame_ids == (
        pack.confirmation_record.post_threshold_recovery_frame_id,
    )
    assert set(result.correction_frame_ids).isdisjoint(result.alleged_interval_crop_ids)


def test_missing_clear_label_and_all_unclear_escalate() -> None:
    pack = _absence_pack()
    clear_ids = tuple(sorted(_absence_authority(pack).clear_crop_ids))

    missing = route_screening(
        _parsed(
            pack,
            probability=0.9,
            observations=_observations(
                clear_ids[:-1],
                (WearStatus.NOT_WORN,) * (len(clear_ids) - 1),
            ),
        ),
        pack,
        _policy(),
    )
    unclear = route_screening(
        _parsed(
            pack,
            probability=0.9,
            observations=_observations(
                clear_ids,
                (WearStatus.UNCLEAR,) * len(clear_ids),
            ),
        ),
        pack,
        _policy(),
    )
    assert missing.decision == ScreeningDecision.ESCALATE
    assert unclear.decision == ScreeningDecision.ESCALATE


def test_model_evidence_class_mismatch_is_computed_and_forces_escalation() -> None:
    pack = _presence_pack()
    result = route_screening(
        _parsed(pack, probability=0.9, evidence_class=EvidenceClass.ABSENCE),
        pack,
        _policy(),
    )
    assert result.conflict_codes == (ScreeningConflictCode.MODEL_EVIDENCE_CLASS_MISMATCH,)
    assert result.decision == ScreeningDecision.ESCALATE


def test_fast_verdict_preserves_typed_content_without_inventing_hearing_records() -> None:
    pack = _presence_pack()
    parsed = _parsed(pack, probability=0.9)
    screening = route_screening(parsed, pack, _policy())

    first = build_fast_verdict(screening, pack)
    second = FastVerdictBuilder().build(screening, pack)

    assert first == second
    assert first.decision == VerdictDecision.ESTABLISHED
    assert first.confidence == parsed.violation_probability
    assert first.recommended_alert_level == AlertLevel.CONFIRMED
    assert first.evidence_citations == parsed.evidence_citations
    assert first.objective_claims == parsed.objective_claims
    assert len(first.prosecution_arguments) == 1
    assert first.prosecution_arguments[0].claim == parsed.prosecution_summary
    # Two geometric citations to the same artifact remain citations but do not
    # duplicate the supporting reference inside the generated argument.
    assert first.prosecution_arguments[0].evidence_refs == (
        parsed.evidence_citations[0].evidence_ref,
    )
    assert first.defense_arguments == ()
    assert first.judge_responses == ()
    assert first.precedent_applications == ()
    assert first.acquisition_log == ()
    assert first.model_response_refs == (
        ArtifactRef(kind=ArtifactKind.MODEL_RESPONSE, artifact_id=parsed.response_id),
    )
    assert canonical_json(first.model_dump(mode="json")) == canonical_json(
        second.model_dump(mode="json")
    )


def test_v2_fast_verdict_isolates_model_narrative_from_authoritative_verdict() -> None:
    pack = _presence_pack()
    parsed = _parsed(pack, probability=0.9)
    model_claim = "The model claims 123 frames and 99 seconds prove the allegation."
    model_rationale = "The model claims an objective duration without authoritative facts."
    parsed = parsed.model_copy(
        update={
            "payload": parsed.payload.model_copy(
                update={
                    "prosecution_summary": model_claim,
                    "rationale_summary": model_rationale,
                }
            )
        }
    )
    policy = ScreeningRoutePolicy(
        low_probability=0.2,
        high_probability=0.8,
        strong_signal_threshold=1.0,
        router_version=DETERMINISTIC_NARRATIVE_ROUTER_VERSION,
    )

    verdict = build_fast_verdict(route_screening(parsed, pack, policy), pack)

    assert verdict.prosecution_arguments[0].claim == (
        "The deterministic screening route established the allegation from cited typed evidence."
    )
    assert verdict.rationale_summary == (
        "The decision follows evidence-pack authority, strictly parsed typed fields, and the "
        "versioned screening policy; model-authored narrative is not decision authority."
    )
    assert model_claim not in canonical_json(verdict.model_dump(mode="json"))
    assert model_rationale not in canonical_json(verdict.model_dump(mode="json"))
    assert parsed.payload.prosecution_summary == model_claim
    assert parsed.payload.rationale_summary == model_rationale


def test_fast_verdict_can_preserve_the_complete_repair_response_chain() -> None:
    pack = _presence_pack()
    parsed = _parsed(pack, probability=0.9)
    screening = route_screening(parsed, pack, _policy())
    response_refs = (
        ArtifactRef(kind=ArtifactKind.MODEL_RESPONSE, artifact_id=SHA_1),
        ArtifactRef(kind=ArtifactKind.MODEL_RESPONSE, artifact_id=parsed.response_id),
    )

    verdict = build_fast_verdict(
        screening,
        pack,
        model_response_refs=response_refs,
    )

    assert verdict.model_response_refs == response_refs
    with pytest.raises(ScreeningRouteError, match="unique, stable"):
        build_fast_verdict(
            screening,
            pack,
            model_response_refs=(response_refs[0],),
        )


def test_absence_fast_verdict_preserves_clear_and_non_clear_observations() -> None:
    pack = _absence_pack()
    authority = _absence_authority(pack)
    clear_ids = tuple(sorted(authority.clear_crop_ids))
    non_clear_ids = tuple(sorted(authority.unclear_crop_ids))
    observations = _observations(
        (*clear_ids, *non_clear_ids),
        (
            *((WearStatus.NOT_WORN,) * len(clear_ids)),
            *((WearStatus.WORN,) * len(non_clear_ids)),
        ),
    )
    screening = route_screening(
        _parsed(pack, probability=0.95, observations=observations),
        pack,
        _policy(),
    )
    verdict = build_fast_verdict(screening, pack)

    assert verdict.decision == VerdictDecision.ESTABLISHED
    assert verdict.observation_sufficiency is not None
    assert verdict.observation_sufficiency.clear_threshold == (authority.clear_threshold)
    assert verdict.observation_sufficiency.required_clear_count == (authority.required_clear_count)
    assert tuple(
        (label.crop_id, label.wear_status) for label in verdict.observation_sufficiency.observations
    ) == tuple((observation.crop_id, observation.wear_status) for observation in observations)


def test_fast_verdict_derives_formal_crop_citations_from_typed_observations() -> None:
    pack = _absence_pack()
    authority = _absence_authority(pack)
    clear_ids = tuple(sorted(authority.clear_crop_ids))
    observations = _observations(
        clear_ids,
        (WearStatus.NOT_WORN,) * len(clear_ids),
    )
    screening = route_screening(
        _parsed(pack, probability=0.95, observations=observations, citations=()),
        pack,
        _policy(),
    )

    verdict = build_fast_verdict(screening, pack)

    assert verdict.decision == VerdictDecision.ESTABLISHED
    assert tuple(
        (citation.evidence_ref.kind, citation.evidence_ref.artifact_id)
        for citation in verdict.evidence_citations
    ) == tuple((ArtifactKind.CROP, crop_id) for crop_id in clear_ids)
    assert all(
        citation.bbox is None and citation.coordinate_space is None
        for citation in verdict.evidence_citations
    )
    assert verdict.prosecution_arguments[0].evidence_refs == tuple(
        ArtifactRef(kind=ArtifactKind.CROP, artifact_id=crop_id) for crop_id in clear_ids
    )


def test_negative_fast_verdict_uses_directional_confidence_and_retains_support() -> None:
    pack = _presence_pack()
    parsed = _parsed(pack, probability=0.1)
    screening = route_screening(parsed, pack, _policy())
    verdict = build_fast_verdict(
        screening,
        pack,
        FastVerdictPolicy(
            established_alert_level=AlertLevel.CONFIRMED,
            not_established_alert_level=AlertLevel.ADVISORY,
        ),
    )
    assert verdict.decision == VerdictDecision.NOT_ESTABLISHED
    assert verdict.confidence == pytest.approx(0.9)
    assert verdict.recommended_alert_level == AlertLevel.ADVISORY
    assert verdict.evidence_citations == parsed.evidence_citations
    assert verdict.prosecution_arguments[0].evidence_refs


def test_fast_verdict_preserves_violation_mismatch_for_l5() -> None:
    pack = _presence_pack()
    parsed = _parsed(
        pack,
        probability=0.9,
        violation_type=ViolationType.FOOD_OR_DRINK_IN_LAB,
    )
    screening = route_screening(parsed, pack, _policy())
    verdict = build_fast_verdict(screening, pack)
    assert verdict.violation_type == ViolationType.FOOD_OR_DRINK_IN_LAB
    assert verdict.violation_type != pack.event.violation_type


def test_fast_verdict_rejects_escalation_but_preserves_unsupported_establishment() -> None:
    pack = _presence_pack()
    escalated = route_screening(_parsed(pack, probability=0.5), pack, _policy())
    with pytest.raises(ScreeningRouteError, match="escalated"):
        build_fast_verdict(escalated, pack)

    unsupported = route_screening(
        _parsed(pack, probability=0.9, citations=()),
        pack,
        _policy(),
    )
    proposal = build_fast_verdict(unsupported, pack)
    assert proposal.decision == VerdictDecision.ESTABLISHED
    assert proposal.evidence_citations == ()
    assert len(proposal.prosecution_arguments) == 1
    assert proposal.prosecution_arguments[0].evidence_refs == ()


def test_router_rejects_cross_pack_scope_and_invalid_policy() -> None:
    pack = _presence_pack()
    other = _absence_pack()
    with pytest.raises(ScreeningRouteError, match="outside the evidence-pack scope"):
        route_screening(_parsed(pack, probability=0.9), other, _policy())
    with pytest.raises(ValueError, match="below"):
        ScreeningRoutePolicy(
            low_probability=0.8,
            high_probability=0.8,
            strong_signal_threshold=0.9,
        )
    with pytest.raises(ValueError, match="positive integer"):
        route_screening(_parsed(pack, probability=0.9), pack, _policy(), version=0)


def test_router_and_builder_validate_typed_policy_and_authority_boundaries() -> None:
    pack = _presence_pack()
    parsed = _parsed(pack, probability=0.9)
    screening = route_screening(parsed, pack, _policy())

    with pytest.raises(TypeError, match="real number"):
        ScreeningRoutePolicy(
            low_probability=True,
            high_probability=0.8,
            strong_signal_threshold=0.9,
        )
    with pytest.raises(ValueError, match="between zero and one"):
        ScreeningRoutePolicy(
            low_probability=-0.1,
            high_probability=0.8,
            strong_signal_threshold=0.9,
        )
    with pytest.raises(TypeError, match="ScreeningRoutePolicy"):
        ScreeningRouter("invalid")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="ScreeningRoutePolicy"):
        route_screening(parsed, pack, "invalid")  # type: ignore[arg-type]

    with pytest.raises(TypeError, match="AlertLevel"):
        FastVerdictPolicy(established_alert_level="CONFIRMED")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="AlertLevel"):
        FastVerdictPolicy(not_established_alert_level="ADVISORY")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="FastVerdictPolicy"):
        FastVerdictBuilder("invalid")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="FastVerdictPolicy"):
        build_fast_verdict(screening, pack, "invalid")  # type: ignore[arg-type]

    wrong_l1 = screening.model_copy(update={"authoritative_l1_score": 0.1})
    with pytest.raises(ScreeningRouteError, match="authority conflicts"):
        build_fast_verdict(wrong_l1, pack)


def test_incomplete_and_empty_absence_packs_cannot_enter_screening_or_verdict() -> None:
    complete = _presence_pack()
    incomplete = _presence_pack(complete=False)
    with pytest.raises(ScreeningRouteError, match="complete evidence pack"):
        route_screening(_parsed(incomplete, probability=0.9), incomplete, _policy())

    screening = route_screening(_parsed(complete, probability=0.9), complete, _policy())
    with pytest.raises(ScreeningRouteError, match="complete evidence pack"):
        build_fast_verdict(screening, incomplete)

    empty_absence = _absence_pack(include_temporal=False)
    with pytest.raises(ScreeningRouteError, match="alleged-interval crops"):
        route_screening(
            _parsed(empty_absence, probability=0.9, citations=()),
            empty_absence,
            _policy(),
        )


def test_fast_verdict_rejects_rewritten_absence_authority() -> None:
    pack = _absence_pack()
    authority = _absence_authority(pack)
    clear_ids = tuple(sorted(authority.clear_crop_ids))
    observations = _observations(
        clear_ids,
        (WearStatus.NOT_WORN,) * len(clear_ids),
    )
    screening = route_screening(
        _parsed(pack, probability=0.9, observations=observations),
        pack,
        _policy(),
    )
    rewritten = screening.model_copy(update={"authoritative_clear_crop_ids": clear_ids[:-1]})
    with pytest.raises(ScreeningRouteError, match="absence authority conflicts"):
        build_fast_verdict(rewritten, pack)
