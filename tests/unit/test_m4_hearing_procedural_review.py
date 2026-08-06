from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from typing import cast

import pytest

from labcourt.application.hearing_procedural_review import (
    DeterministicHearingProceduralReviewVerifier,
    HearingProceduralReviewVerificationError,
)
from labcourt.config_loader import load_config
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.config import AppConfig
from labcourt.contracts.enums import (
    AlertLevel,
    ArgumentStance,
    ArtifactKind,
    CropSource,
    JudgeDisposition,
    MediaAccess,
    MediaAvailability,
    MediaType,
    ModelParseStatus,
    PrivacyPolicy,
    PrivacyReasonCode,
    ProceduralDefectCode,
    VerdictDecision,
    VlmRole,
)
from labcourt.contracts.events import CandidateEvent, derive_case_id
from labcourt.contracts.evidence import (
    Crop,
    EvidencePack,
    EvidencePackDraft,
    PrivacyReceipt,
    TrackSummary,
)
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.hearing import (
    DefenderModelPayload,
    HearingModelParseReceipt,
    HearingModelRequest,
    HearingModelResponse,
    HearingPrecedentDegradedReason,
    HearingPrecedentRetrievalReceipt,
    HearingPrecedentRetrievalStatus,
    HearingRecord,
    HearingRoleOutput,
    HearingRound,
    HearingSession,
    HearingSessionEntryStatus,
    HearingUsageReceipt,
    JudgeFinalDecisionPayload,
    JudgeModelPayload,
    ProsecutorModelPayload,
    derive_hearing_model_response_id,
)
from labcourt.contracts.m3_models import EvidenceCitation, PromptManifest, VlmCallBudget
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.screening import VLMMediaRef
from labcourt.contracts.storage import ArtifactRef, ClosureReport
from labcourt.contracts.verdicts import Argument, JudgeResponse, ProceduralReview
from labcourt.domain.evidence_authority import HearingEvidenceGrant
from labcourt.domain.hearing_fsm import HearingCallClosure
from labcourt.domain.hearing_verdict_builder import build_hearing_verdict
from labcourt.domain.procedural_gate import ArtifactBounds
from labcourt.ports.evidence_repository import EvidenceRepository

ROOT = Path(__file__).parents[2]
M2_FIXTURES = ROOT / "tests" / "fixtures" / "m2"
RUN_ID = "run-m4-hearing-review"
SCREENING_ID = sha256_hex(["m4-review-screening"])
HEARING_BUNDLE = sha256_hex(["m4-review-prompt-bundle"])


def _sha(label: str) -> str:
    return sha256_hex(["m4-hearing-review-test", label])


def _ref(kind: ArtifactKind, artifact_id: str) -> ArtifactRef:
    return ArtifactRef(kind=kind, artifact_id=artifact_id)


def _event() -> CandidateEvent:
    return CandidateEvent.model_validate_json(
        (M2_FIXTURES / "candidate-event-presence.json").read_text(encoding="utf-8")
    )


def _manifest() -> RunManifest:
    return RunManifest.model_validate_json(
        (M2_FIXTURES / "run-manifest-fake.json").read_text(encoding="utf-8")
    )


def _crop(event: CandidateEvent, index: int) -> Crop:
    frame_id = f"{event.camera_id}:{event.stream_id}:{event.trigger_frame}"
    sources = tuple(
        sorted(
            (
                _ref(ArtifactKind.FRAME, frame_id),
                _ref(ArtifactKind.DETECTION, f"review-detection-{index}"),
            ),
            key=lambda ref: ref.sort_key,
        )
    )
    bbox = BBoxXYXY(
        x1=20 + index * 140,
        y1=30,
        x2=120 + index * 140,
        y2=230,
    )
    media_sha = _sha(f"crop-media-{index}")
    return Crop(
        frame_id=frame_id,
        source=CropSource.DETECTION_FOCUS,
        bbox=bbox,
        source_refs=sources,
        local_path=f"{RUN_ID}/frames/{media_sha}.png",
        availability=MediaAvailability.AVAILABLE,
        source_media_sha256=_sha(f"crop-source-{index}"),
        pixel_sha256=_sha(f"crop-pixels-{index}"),
        media_sha256=media_sha,
        output_width=bbox.width,
        output_height=bbox.height,
        size_bytes=512,
        media_type=MediaType.IMAGE_PNG,
        encoding_version="png-v1",
        privacy_receipt=PrivacyReceipt(
            policy=PrivacyPolicy.FULL_REDACTION,
            transform_version="privacy-v1",
            media_access=MediaAccess.LOCAL_ONLY,
            reason_code=PrivacyReasonCode.POLICY_LOCAL_ONLY,
            input_refs=sources,
            fill_rgb=(0, 0, 0),
        ),
        primary_track_ref=event.primary_track_ref,
        tags={"zone_id": event.zone_id},
    )


def _pack(crop_count: int) -> EvidencePack:
    event = _event()
    crops = tuple(
        sorted(
            (_crop(event, index) for index in range(crop_count)),
            key=lambda item: (item.frame_id, item.crop_id),
        )
    )
    draft = EvidencePackDraft(
        run_id=RUN_ID,
        case_id=derive_case_id(event.event_id),
        version=1,
        event=event,
        key_frame_ids=(f"{event.camera_id}:{event.stream_id}:{event.trigger_frame}",),
        focus_crops=crops,
        objective_facts=event.objective_facts,
        track_summary=TrackSummary(
            primary_track_ref=event.primary_track_ref,
            start_frame=event.start_frame,
            end_frame_exclusive=event.end_frame_exclusive,
            observed_frame_count=event.end_frame_exclusive - event.start_frame,
        ),
        confirmation_record=event.confirmation,
        manifest_id=event.manifest_id,
    )
    closure = ClosureReport(
        run_id=RUN_ID,
        root_ref=_ref(ArtifactKind.CASE, draft.case_id),
        manifest_id=draft.manifest_id,
        input_sha256=draft.closure_input_sha256,
        checked_refs=draft.expected_closure_refs(),
    )
    return EvidencePack.model_validate(
        {
            **draft.model_dump(mode="python", exclude={"pack_id"}),
            "closure_report": closure,
        }
    )


def _current_closure(pack: EvidencePack) -> ClosureReport:
    root = _ref(ArtifactKind.EVIDENCE_PACK, pack.pack_id)
    refs = {ref.sort_key: ref for ref in (*pack.expected_closure_refs(), root)}
    return ClosureReport(
        run_id=pack.run_id,
        root_ref=root,
        manifest_id=pack.manifest_id,
        input_sha256=pack.closure_input_sha256,
        checked_refs=tuple(refs[key] for key in sorted(refs)),
    )


def _prompt(role: VlmRole) -> PromptManifest:
    return PromptManifest(
        prompt_id=f"hearing_{role.value.lower()}_v1",
        role=role,
        template_sha256=_sha(f"template-{role.value}"),
        output_schema_sha256=_sha(f"schema-{role.value}"),
        prompt_bundle_sha256=HEARING_BUNDLE,
        renderer_version="jinja-3-1-6",
    )


def _argument(
    stance: ArgumentStance,
    label: str,
    evidence_ref: ArtifactRef,
) -> Argument:
    return Argument(
        stance=stance,
        claim=f"Structured {label} claim.",
        evidence_refs=(evidence_ref,),
        uncertainty=0.1,
    )


def _request(
    *,
    config: AppConfig,
    manifest: RunManifest,
    session: HearingSession,
    pack: EvidencePack,
    retrieval: HearingPrecedentRetrievalReceipt,
    role: VlmRole,
    crop: Crop,
    prosecutor_output_id: str | None = None,
    defender_output_id: str | None = None,
) -> HearingModelRequest:
    profile_name = {
        VlmRole.PROSECUTOR: config.hearing.prosecutor_profile,
        VlmRole.DEFENDER: config.hearing.defender_profile,
        VlmRole.JUDGE: config.hearing.judge_profile,
    }[role]
    component_name = {
        VlmRole.PROSECUTOR: "prosecutor",
        VlmRole.DEFENDER: "defender",
        VlmRole.JUDGE: "judge",
    }[role]
    profile = config.providers[profile_name]
    component = manifest.models[component_name]
    media = VLMMediaRef(
        crop_id=crop.crop_id,
        media_sha256=crop.media_sha256,
        local_path=crop.local_path or "",
        source=crop.source,
        media_access=crop.privacy_receipt.media_access,
        privacy_policy=crop.privacy_receipt.policy,
        privacy_transform_version=crop.privacy_receipt.transform_version,
        width=crop.output_width,
        height=crop.output_height,
    )
    return HearingModelRequest(
        run_id=pack.run_id,
        case_id=pack.case_id,
        hearing_session_id=session.session_id,
        round_index=1,
        prior_acquisition_rounds=0,
        prior_rework_rounds=0,
        current_evidence_pack_id=pack.pack_id,
        current_evidence_pack_version=pack.version,
        screening_ref=_ref(ArtifactKind.SCREENING_RESULT, SCREENING_ID),
        violation_type=pack.event.violation_type,
        evidence_class=pack.event.evidence_class,
        role=role,
        provider_profile=profile_name,
        provider=profile.provider,
        model=profile.model,
        revision=profile.revision,
        model_manifest_id=component.model_manifest_id,
        execution_location=profile.execution_location,
        prompt_manifest=_prompt(role),
        hearing_prompt_bundle_sha256=HEARING_BUNDLE,
        rendered_prompt_sha256=_sha(f"rendered-{role.value}-{crop.crop_id}"),
        hearing_context_sha256=_sha(f"context-{role.value}-{crop.crop_id}"),
        media=(media,),
        allowed_evidence_refs=(_ref(ArtifactKind.CROP, crop.crop_id),),
        allowed_precedent_refs=(),
        prosecutor_output_ref=(
            _ref(ArtifactKind.PARSED_MODEL_OUTPUT, prosecutor_output_id)
            if prosecutor_output_id is not None
            else None
        ),
        defender_output_ref=(
            _ref(ArtifactKind.PARSED_MODEL_OUTPUT, defender_output_id)
            if defender_output_id is not None
            else None
        ),
        precedent_retrieval_degraded=True,
        precedent_retrieval_receipt_id=retrieval.receipt_id,
        precedent_retrieval_receipt_sha256=retrieval.receipt_sha256,
        temperature=0.0,
        seed=7,
        budget=VlmCallBudget(
            max_images=1,
            max_input_pixels=crop.output_width * crop.output_height,
            max_input_tokens=100,
            max_output_tokens=100,
            pricing_currency="USD",
            input_cost_per_million_tokens=profile.input_cost_per_million_tokens,
            output_cost_per_million_tokens=profile.output_cost_per_million_tokens,
            max_estimated_cost=1.0,
            max_response_bytes=10_000,
            max_json_depth=16,
            max_json_fields=128,
            max_string_chars=4_096,
            timeout_seconds=profile.timeout_seconds,
        ),
        manifest_id=pack.manifest_id,
    )


def _call(
    request: HearingModelRequest,
    payload: ProsecutorModelPayload | DefenderModelPayload | JudgeModelPayload,
) -> tuple[HearingCallClosure, HearingRoleOutput]:
    content_sha = _sha(f"response-{request.request_id}")
    response_id = derive_hearing_model_response_id(
        request.run_id,
        request.request_id,
        content_sha,
    )
    response = HearingModelResponse(
        run_id=request.run_id,
        case_id=request.case_id,
        hearing_session_id=request.hearing_session_id,
        round_index=request.round_index,
        prior_acquisition_rounds=request.prior_acquisition_rounds,
        prior_rework_rounds=request.prior_rework_rounds,
        current_evidence_pack_id=request.current_evidence_pack_id,
        current_evidence_pack_version=request.current_evidence_pack_version,
        role=request.role,
        attempt_index=request.attempt_index,
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        cache_key=request.cache_key,
        raw_response_ref=f"{request.run_id}/model_responses/{response_id}.json",
        content_sha256=content_sha,
        size_bytes=100,
        input_tokens=10,
        output_tokens=10,
        latency_ms=5,
        model_manifest_id=request.model_manifest_id,
        manifest_id=request.manifest_id,
    )
    parse = HearingModelParseReceipt(
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
        parser_version="strict-json-v1",
        output_schema_sha256=request.prompt_manifest.output_schema_sha256,
        status=ModelParseStatus.PARSED,
        parsed_payload_sha256=payload.payload_sha256,
        manifest_id=request.manifest_id,
    )
    request_ref = _ref(ArtifactKind.MODEL_REQUEST, request.request_id)
    response_ref = _ref(ArtifactKind.MODEL_RESPONSE, response.response_id)
    parse_ref = _ref(ArtifactKind.MODEL_PARSE_RECEIPT, parse.parse_receipt_id)
    usage = HearingUsageReceipt(
        run_id=request.run_id,
        case_id=request.case_id,
        hearing_session_id=request.hearing_session_id,
        round_index=request.round_index,
        role=request.role,
        request_ref=request_ref,
        response_ref=response_ref,
        input_images=1,
        input_pixels=sum(item.width * item.height for item in request.media),
        input_tokens=response.input_tokens,
        output_tokens=response.output_tokens,
        latency_ms=response.latency_ms,
        retry_count=0,
        estimated_cost=request.budget.estimate_cost(
            input_tokens=response.input_tokens,
            output_tokens=response.output_tokens,
        ),
        manifest_id=request.manifest_id,
    )
    output = HearingRoleOutput(
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
        request_ref=request_ref,
        response_ref=response_ref,
        parse_receipt_ref=parse_ref,
        prosecutor_output_id=(
            request.prosecutor_output_ref.artifact_id
            if request.prosecutor_output_ref is not None
            else None
        ),
        defender_output_id=(
            request.defender_output_ref.artifact_id
            if request.defender_output_ref is not None
            else None
        ),
        precedent_retrieval_degraded=request.precedent_retrieval_degraded,
        precedent_retrieval_receipt_id=request.precedent_retrieval_receipt_id,
        precedent_retrieval_receipt_sha256=request.precedent_retrieval_receipt_sha256,
        payload=payload,
        manifest_id=request.manifest_id,
    )
    return (
        HearingCallClosure(
            request=request,
            response=response,
            parse_receipt=parse,
            usage=usage,
        ),
        output,
    )


class _EvidenceAuthority:
    def __init__(
        self,
        manifest: RunManifest,
        pack: EvidencePack,
        closure: ClosureReport,
    ) -> None:
        self._manifest = manifest
        self._pack = pack
        self._closure = closure

    def load_run_manifest(self, run_id: str) -> RunManifest:
        assert run_id == self._pack.run_id
        return self._manifest

    def load_pack(self, run_id: str, pack_id: str) -> EvidencePack:
        assert (run_id, pack_id) == (self._pack.run_id, self._pack.pack_id)
        return self._pack

    def verify_current_pack(self, run_id: str, pack_id: str) -> ClosureReport:
        assert (run_id, pack_id) == (self._pack.run_id, self._pack.pack_id)
        return self._closure


@dataclass(frozen=True)
class _Rig:
    config: AppConfig
    manifest: RunManifest
    pack: EvidencePack
    closure: ClosureReport
    record: HearingRecord
    call_history: tuple[HearingCallClosure, ...]
    grant: HearingEvidenceGrant
    verifier: DeterministicHearingProceduralReviewVerifier


def _rig(
    *,
    crop_count: int = 1,
    disclosed_crop_by_role: dict[VlmRole, int] | None = None,
    prosecutor_citation_index: int | None = None,
) -> _Rig:
    config = load_config(ROOT / "configs" / "demo.yaml")
    manifest = _manifest()
    pack = _pack(crop_count)
    assert manifest.manifest_id == pack.manifest_id
    assert manifest.config_sha256 == config.config_sha256
    selected = disclosed_crop_by_role or {
        VlmRole.PROSECUTOR: 0,
        VlmRole.DEFENDER: 0,
        VlmRole.JUDGE: 0,
    }
    prosecutor_citation = (
        selected[VlmRole.PROSECUTOR]
        if prosecutor_citation_index is None
        else prosecutor_citation_index
    )
    session = HearingSession(
        run_id=pack.run_id,
        case_id=pack.case_id,
        screening_id=SCREENING_ID,
        entry_status=HearingSessionEntryStatus.ESCALATED,
        initial_evidence_pack_id=pack.pack_id,
        initial_evidence_pack_version=pack.version,
        acquisition_round_limit=config.hearing.max_acquisition_rounds,
        rework_round_limit=config.hearing.max_rework_rounds,
        max_total_images=config.hearing.max_total_images,
        max_total_output_tokens=config.hearing.max_total_output_tokens,
        hearing_prompt_bundle_sha256=HEARING_BUNDLE,
        prosecutor_model_manifest_id=manifest.models["prosecutor"].model_manifest_id,
        defender_model_manifest_id=manifest.models["defender"].model_manifest_id,
        judge_model_manifest_id=manifest.models["judge"].model_manifest_id,
        manifest_id=pack.manifest_id,
    )
    retrieval = HearingPrecedentRetrievalReceipt(
        run_id=pack.run_id,
        case_id=pack.case_id,
        hearing_session_id=session.session_id,
        round_index=1,
        prior_acquisition_rounds=0,
        prior_rework_rounds=0,
        current_evidence_pack_id=pack.pack_id,
        current_evidence_pack_version=pack.version,
        evidence_class=pack.event.evidence_class,
        violation_type=pack.event.violation_type,
        rule_version=pack.event.rule_version,
        top_k=config.hearing.precedent_top_k,
        query_sha256=_sha("precedent-query"),
        candidate_snapshot_sha256=_sha("candidate-snapshot"),
        visible_snapshot_sha256=_sha("visible-snapshot"),
        status=HearingPrecedentRetrievalStatus.DEGRADED,
        degraded_reason=HearingPrecedentDegradedReason.PRECEDENT_INDEX_UNAVAILABLE,
        retriever_version="fake-retriever-v1",
        retriever_manifest_id=_sha("retriever-manifest"),
        manifest_id=pack.manifest_id,
    )
    prosecution_argument = _argument(
        ArgumentStance.PROSECUTION,
        "prosecution",
        _ref(ArtifactKind.CROP, pack.crops[prosecutor_citation].crop_id),
    )
    defense_argument = _argument(
        ArgumentStance.DEFENSE,
        "defense",
        _ref(
            ArtifactKind.CROP,
            pack.crops[selected[VlmRole.DEFENDER]].crop_id,
        ),
    )
    prosecutor_payload = ProsecutorModelPayload(
        arguments=(prosecution_argument,),
        case_summary="The prosecution presents one bounded claim.",
    )
    defender_payload = DefenderModelPayload(
        arguments=(defense_argument,),
        case_summary="The defense presents one bounded objection.",
    )
    judge_payload = JudgeModelPayload(
        judge_responses=(
            JudgeResponse(
                defense_argument_id=defense_argument.argument_id,
                disposition=JudgeDisposition.REJECTED,
                response_summary="The exact defense argument is addressed.",
            ),
        ),
        outcome=JudgeFinalDecisionPayload(
            decision=VerdictDecision.ESTABLISHED,
            confidence=0.9,
            recommended_alert_level=AlertLevel.CONFIRMED,
            rationale_summary="The structured evidence supports the proposal.",
            evidence_citations=(
                EvidenceCitation(
                    evidence_ref=_ref(
                        ArtifactKind.CROP,
                        pack.crops[selected[VlmRole.JUDGE]].crop_id,
                    )
                ),
            ),
        ),
    )
    prosecutor_request = _request(
        config=config,
        manifest=manifest,
        session=session,
        pack=pack,
        retrieval=retrieval,
        role=VlmRole.PROSECUTOR,
        crop=pack.crops[selected[VlmRole.PROSECUTOR]],
    )
    prosecutor_call, prosecutor_output = _call(
        prosecutor_request,
        prosecutor_payload,
    )
    defender_request = _request(
        config=config,
        manifest=manifest,
        session=session,
        pack=pack,
        retrieval=retrieval,
        role=VlmRole.DEFENDER,
        crop=pack.crops[selected[VlmRole.DEFENDER]],
        prosecutor_output_id=prosecutor_output.output_id,
    )
    defender_call, defender_output = _call(defender_request, defender_payload)
    judge_request = _request(
        config=config,
        manifest=manifest,
        session=session,
        pack=pack,
        retrieval=retrieval,
        role=VlmRole.JUDGE,
        crop=pack.crops[selected[VlmRole.JUDGE]],
        prosecutor_output_id=prosecutor_output.output_id,
        defender_output_id=defender_output.output_id,
    )
    judge_call, judge_output = _call(judge_request, judge_payload)
    hearing_round = HearingRound(
        run_id=pack.run_id,
        case_id=pack.case_id,
        hearing_session_id=session.session_id,
        round_index=1,
        prior_acquisition_rounds=0,
        prior_rework_rounds=0,
        current_evidence_pack_id=pack.pack_id,
        current_evidence_pack_version=pack.version,
        precedent_retrieval_degraded=True,
        precedent_retrieval_receipt=retrieval,
        prosecutor_output=prosecutor_output,
        defender_output=defender_output,
        judge_output=judge_output,
        manifest_id=pack.manifest_id,
    )
    history = (prosecutor_call, defender_call, judge_call)
    record = HearingRecord(
        run_id=pack.run_id,
        case_id=pack.case_id,
        version=1,
        session=session,
        screening_id=SCREENING_ID,
        initial_evidence_pack_id=pack.pack_id,
        initial_evidence_pack_version=pack.version,
        acquisition_round_limit=config.hearing.max_acquisition_rounds,
        rework_round_limit=config.hearing.max_rework_rounds,
        rounds=(hearing_round,),
        model_request_refs=tuple(
            sorted((call.request_ref for call in history), key=lambda ref: ref.sort_key)
        ),
        model_response_refs=tuple(
            sorted((call.response_ref for call in history), key=lambda ref: ref.sort_key)
        ),
        parse_receipt_refs=tuple(
            sorted((call.parse_receipt_ref for call in history), key=lambda ref: ref.sort_key)
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
        manifest_id=pack.manifest_id,
    )
    granted_crops = tuple(
        sorted(
            {pack.crops[index].crop_id: pack.crops[index] for index in selected.values()}.values(),
            key=lambda item: item.crop_id,
        )
    )
    granted_refs = tuple(
        sorted(
            (_ref(ArtifactKind.CROP, crop.crop_id) for crop in granted_crops),
            key=lambda ref: ref.sort_key,
        )
    )
    grant = HearingEvidenceGrant(
        run_id=pack.run_id,
        case_id=pack.case_id,
        latest_evidence_pack_id=pack.pack_id,
        latest_evidence_pack_version=pack.version,
        allowed_evidence_refs=granted_refs,
        artifact_bounds=tuple(
            ArtifactBounds(
                artifact_ref=_ref(ArtifactKind.CROP, crop.crop_id),
                width=crop.output_width,
                height=crop.output_height,
            )
            for crop in granted_crops
        ),
    )
    closure = _current_closure(pack)
    verifier = DeterministicHearingProceduralReviewVerifier(
        config,
        cast(
            EvidenceRepository,
            _EvidenceAuthority(manifest, pack, closure),
        ),
    )
    return _Rig(
        config=config,
        manifest=manifest,
        pack=pack,
        closure=closure,
        record=record,
        call_history=history,
        grant=grant,
        verifier=verifier,
    )


def _review(
    rig: _Rig,
    *,
    grant: HearingEvidenceGrant | None = None,
) -> ProceduralReview:
    verdict, binding = build_hearing_verdict(
        rig.record,
        rig.pack.event.violation_type,
    )
    return rig.verifier.rebuild_review(
        record=rig.record,
        verdict=verdict,
        binding=binding,
        evidence_pack=rig.pack,
        current_closure=rig.closure,
        call_history=rig.call_history,
        evidence_grant=rig.grant if grant is None else grant,
        review_version=1,
    )


def test_clean_hearing_rebuilds_a_passing_review() -> None:
    review = _review(_rig())

    assert review.passed is True
    assert review.defects == ()


def test_cross_role_reference_is_rejected_even_when_union_grant_contains_it() -> None:
    rig = _rig(
        crop_count=2,
        disclosed_crop_by_role={
            VlmRole.PROSECUTOR: 0,
            VlmRole.DEFENDER: 0,
            VlmRole.JUDGE: 1,
        },
        prosecutor_citation_index=1,
    )

    review = _review(rig)

    assert review.passed is False
    assert ProceduralDefectCode.FABRICATED_EVIDENCE_REFERENCE in {
        defect.code for defect in review.defects
    }
    assert {ref.artifact_id for ref in rig.grant.allowed_evidence_refs} == {
        crop.crop_id for crop in rig.pack.crops
    }


def test_overclaimed_disclosure_grant_fails_as_authority_error() -> None:
    rig = _rig(crop_count=2)
    extra = rig.pack.crops[1]
    refs = tuple(
        sorted(
            (
                *rig.grant.allowed_evidence_refs,
                _ref(ArtifactKind.CROP, extra.crop_id),
            ),
            key=lambda ref: ref.sort_key,
        )
    )
    bounds = tuple(
        sorted(
            (
                *rig.grant.artifact_bounds,
                ArtifactBounds(
                    artifact_ref=_ref(ArtifactKind.CROP, extra.crop_id),
                    width=extra.output_width,
                    height=extra.output_height,
                ),
            ),
            key=lambda item: item.sort_key,
        )
    )
    forged = replace(
        rig.grant,
        allowed_evidence_refs=refs,
        artifact_bounds=bounds,
    )

    with pytest.raises(
        HearingProceduralReviewVerificationError,
        match="actual provider disclosure",
    ):
        _review(rig, grant=forged)


def test_missing_call_and_stale_closure_fail_before_l5() -> None:
    rig = _rig()
    verdict, binding = build_hearing_verdict(
        rig.record,
        rig.pack.event.violation_type,
    )

    with pytest.raises(
        HearingProceduralReviewVerificationError,
        match="exact successful call history",
    ):
        rig.verifier.rebuild_review(
            record=rig.record,
            verdict=verdict,
            binding=binding,
            evidence_pack=rig.pack,
            current_closure=rig.closure,
            call_history=rig.call_history[:-1],
            evidence_grant=rig.grant,
            review_version=1,
        )

    stale = rig.closure.model_copy(update={"input_sha256": _sha("stale-closure")})
    with pytest.raises(
        HearingProceduralReviewVerificationError,
        match="current physical evidence",
    ):
        rig.verifier.rebuild_review(
            record=rig.record,
            verdict=verdict,
            binding=binding,
            evidence_pack=rig.pack,
            current_closure=stale,
            call_history=rig.call_history,
            evidence_grant=rig.grant,
            review_version=1,
        )
