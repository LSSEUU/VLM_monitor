from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType

import pytest

from labcourt.adapters.hearing_prompt_renderer import (
    M8_HEARING_PROMPT_V2_DEFINITIONS,
    HearingJinjaPromptCatalog,
)
from labcourt.application.hearing_model_parser import (
    finalize_hearing_parse,
    inspect_hearing_response,
)
from labcourt.application.hearing_request import (
    FROZEN_M4_PROMPT_BUNDLE_SHA256,
    M8_HEARING_PROMPT_V2_BUNDLE_SHA256,
    HearingBudgetUsage,
    HearingRequestGeneration,
    HearingRequestPreparationError,
    HearingRequestPreparationErrorCode,
    PreparedHearingRequest,
    prepare_hearing_repair_request,
    prepare_primary_hearing_request,
)
from labcourt.config_loader import load_config
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.config import AppConfig
from labcourt.contracts.detections import Keypoint
from labcourt.contracts.enums import (
    AcquisitionAction,
    AnchorType,
    ArgumentStance,
    ArtifactKind,
    AssociationMethod,
    CropSource,
    ExecutionLocation,
    MediaAccess,
    MediaAvailability,
    MediaType,
    ObservationSource,
    PpeType,
    PrivacyPolicy,
    PrivacyReasonCode,
    ProviderTransport,
    VlmRole,
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
from labcourt.contracts.hearing import (
    DefenderModelPayload,
    HearingCycleScope,
    HearingModelResponse,
    HearingPrecedentRetrievalReceipt,
    HearingPrecedentRetrievalStatus,
    HearingRoleOutput,
    HearingSession,
    HearingSessionEntryStatus,
    ProsecutorModelPayload,
    derive_hearing_model_response_id,
)
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.storage import ArtifactRef
from labcourt.contracts.verdicts import Argument
from labcourt.domain.evidence_authority import (
    EvidenceAuthority,
    derive_evidence_authority,
)
from labcourt.schema_export import expected_schema_files

ROOT = Path(__file__).parents[2]


def _load_evidence_helpers() -> ModuleType:
    module_name = "_labcourt_test_m4_evidence_authority_helpers"
    specification = importlib.util.spec_from_file_location(
        module_name,
        ROOT / "tests" / "unit" / "test_m4_evidence_authority.py",
    )
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules[module_name] = module
    specification.loader.exec_module(module)
    return module


evidence_helpers = _load_evidence_helpers()


def _sha(label: str) -> str:
    return sha256_hex(["m4-hearing-request-test", label])


def _ref(kind: ArtifactKind, label: str) -> ArtifactRef:
    return ArtifactRef(kind=kind, artifact_id=_sha(label))


def _catalog(
    *,
    changed_judge_schema: bool = False,
    m8_v2: bool = False,
) -> HearingJinjaPromptCatalog:
    schemas = expected_schema_files()
    documents = {
        "hearing_prosecutor_v1": canonical_json(
            json.loads(schemas["prosecutor-model-payload.schema.json"])
        ),
        "hearing_defender_v1": canonical_json(
            json.loads(schemas["defender-model-payload.schema.json"])
        ),
        "hearing_judge_v1": canonical_json(json.loads(schemas["judge-model-payload.schema.json"])),
    }
    if changed_judge_schema:
        documents["hearing_judge_v1"] = canonical_json({"type": "array"})
    if m8_v2:
        return HearingJinjaPromptCatalog(
            output_schema_json_by_prompt=documents,
            definitions=M8_HEARING_PROMPT_V2_DEFINITIONS,
        )
    return HearingJinjaPromptCatalog(output_schema_json_by_prompt=documents)


def _closed_pack(manifest: RunManifest) -> EvidencePack:
    source = evidence_helpers._pack()
    event = source.event.model_copy(update={"manifest_id": manifest.manifest_id})
    draft = EvidencePackDraft(
        run_id=source.run_id,
        case_id=source.case_id,
        version=1,
        event=event,
        key_frame_ids=source.key_frame_ids,
        focus_crops=source.focus_crops,
        objective_facts=event.objective_facts,
        track_summary=source.track_summary,
        confirmation_record=event.confirmation,
        manifest_id=manifest.manifest_id,
    )
    return evidence_helpers._close(draft)


def _closed_absence_pack(manifest: RunManifest) -> EvidencePack:
    payload = json.loads(
        (ROOT / "tests/fixtures/m2/candidate-event-absence-strict.json").read_text(encoding="utf-8")
    )
    payload.pop("event_id", None)
    payload["manifest_id"] = manifest.manifest_id
    event = CandidateEvent.model_validate(payload)
    temporal: list[Crop] = []
    for frame_index in (0, 75, 149):
        frame_id = f"{event.camera_id}:{event.stream_id}:{frame_index}"
        frame_ref = ArtifactRef(kind=ArtifactKind.FRAME, artifact_id=frame_id)
        media_sha = _sha(f"absence-media-{frame_index}")
        preserved = BBoxXYXY(x1=10, y1=10, x2=90, y2=55)
        temporal.append(
            Crop(
                frame_id=frame_id,
                source=CropSource.ANCHOR_FOCUS,
                bbox=BBoxXYXY(x1=0, y1=0, x2=100, y2=100),
                source_refs=(frame_ref,),
                local_path=f"{evidence_helpers.RUN_ID}/frames/{media_sha}.png",
                availability=MediaAvailability.AVAILABLE,
                source_media_sha256=_sha(f"absence-source-{frame_index}"),
                pixel_sha256=_sha(f"absence-pixel-{frame_index}"),
                media_sha256=media_sha,
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
        )
    crops = tuple(temporal)
    return evidence_helpers._close(
        EvidencePackDraft(
            run_id=evidence_helpers.RUN_ID,
            case_id=derive_case_id(event.event_id),
            version=1,
            event=event,
            key_frame_ids=tuple(
                f"{event.camera_id}:{event.stream_id}:{index}" for index in (0, 75, 149, 150, 151)
            ),
            temporal_crops=crops,
            objective_facts=event.objective_facts,
            track_summary=TrackSummary(
                primary_track_ref=event.primary_track_ref,
                start_frame=0,
                end_frame_exclusive=152,
                observed_frame_count=151,
            ),
            confirmation_record=event.confirmation,
            observation_sufficiency_input=ObservationSufficiencyInput(
                clear_crop_ids=tuple(sorted(crop.crop_id for crop in crops)),
                clear_threshold=0.65,
                required_clear_count=2,
                selected_by_observability=True,
            ),
            manifest_id=manifest.manifest_id,
        )
    )


def _retrieval(
    session: HearingSession,
    pack: EvidencePack,
    config: AppConfig,
    manifest: RunManifest,
    *,
    cycle_index: int = 1,
    prior_acquisitions: int = 0,
    prior_reworks: int = 0,
) -> HearingPrecedentRetrievalReceipt:
    return HearingPrecedentRetrievalReceipt(
        run_id=pack.run_id,
        case_id=pack.case_id,
        hearing_session_id=session.session_id,
        round_index=cycle_index,
        prior_acquisition_rounds=prior_acquisitions,
        prior_rework_rounds=prior_reworks,
        current_evidence_pack_id=pack.pack_id,
        current_evidence_pack_version=pack.version,
        evidence_class=pack.event.evidence_class,
        violation_type=pack.event.violation_type,
        rule_version=manifest.rule_version,
        top_k=config.hearing.precedent_top_k,
        query_sha256=_sha(f"query-{cycle_index}"),
        candidate_snapshot_sha256=_sha(f"candidate-{cycle_index}"),
        visible_snapshot_sha256=_sha(f"visible-{cycle_index}"),
        status=HearingPrecedentRetrievalStatus.SUCCESS,
        retriever_version="fake-retriever-v1",
        retriever_manifest_id=_sha("retriever"),
        embedding_model_manifest_id=(manifest.models["text_embedding"].model_manifest_id),
        manifest_id=manifest.manifest_id,
    )


def _scope(
    session: HearingSession,
    retrieval: HearingPrecedentRetrievalReceipt,
) -> HearingCycleScope:
    return HearingCycleScope(
        run_id=retrieval.run_id,
        case_id=retrieval.case_id,
        hearing_session_id=session.session_id,
        cycle_index=retrieval.round_index,
        prior_acquisition_rounds=retrieval.prior_acquisition_rounds,
        prior_rework_rounds=retrieval.prior_rework_rounds,
        cycle_evidence_pack_id=retrieval.current_evidence_pack_id,
        cycle_evidence_pack_version=retrieval.current_evidence_pack_version,
        initial_trigger_review_ref=retrieval.initial_trigger_review_ref,
        initial_defect_codes=retrieval.initial_defect_codes,
        rework_review_ref=retrieval.rework_review_ref,
        rework_defect_codes=retrieval.rework_defect_codes,
        manifest_id=retrieval.manifest_id,
    )


@dataclass(frozen=True, slots=True)
class Scenario:
    config: AppConfig
    manifest: RunManifest
    pack: EvidencePack
    authority: EvidenceAuthority
    session: HearingSession
    retrieval: HearingPrecedentRetrievalReceipt
    scope: HearingCycleScope
    catalog: HearingJinjaPromptCatalog


def _scenario(
    *,
    absence: bool = False,
    external_prosecutor: bool = False,
    max_input_pixels: int | None = None,
    max_prompt_bytes: int | None = None,
) -> Scenario:
    base_config = load_config(ROOT / "configs" / "demo.yaml")
    evidence_config = base_config.evidence.model_copy(
        update={"privacy_transform_version": "privacy-v1"}
    )
    screening_updates: dict[str, int] = {}
    if max_input_pixels is not None:
        screening_updates["max_input_pixels"] = max_input_pixels
    if max_prompt_bytes is not None:
        screening_updates["max_prompt_bytes"] = max_prompt_bytes
    screening = base_config.screening.model_copy(update=screening_updates)
    providers = dict(base_config.providers)
    if external_prosecutor:
        providers[base_config.hearing.prosecutor_profile] = providers[
            base_config.hearing.prosecutor_profile
        ].model_copy(
            update={
                "provider": "external-test",
                "execution_location": ExecutionLocation.EXTERNAL,
                "transport": ProviderTransport.HTTP,
                "endpoint_env": "LABCOURT_TEST_ENDPOINT",
                "api_key_env": "LABCOURT_TEST_API_KEY",
            }
        )
    config = base_config.model_copy(
        update={
            "evidence": evidence_config,
            "screening": screening,
            "providers": providers,
        }
    )
    base_manifest = RunManifest.model_validate_json(
        (ROOT / "tests" / "fixtures" / "m2" / "run-manifest-fake.json").read_text(encoding="utf-8")
    )
    models = dict(base_manifest.models)
    if external_prosecutor:
        models["prosecutor"] = models["prosecutor"].model_copy(update={"provider": "external-test"})
    manifest = base_manifest.model_copy(
        update={
            "config_sha256": config.config_sha256,
            "privacy_transform_version": "privacy-v1",
            "models": models,
        }
    )
    pack = _closed_absence_pack(manifest) if absence else _closed_pack(manifest)
    session = HearingSession(
        run_id=pack.run_id,
        case_id=pack.case_id,
        screening_id=_sha("screening"),
        entry_status=HearingSessionEntryStatus.ESCALATED,
        initial_evidence_pack_id=pack.pack_id,
        initial_evidence_pack_version=pack.version,
        acquisition_round_limit=config.hearing.max_acquisition_rounds,
        rework_round_limit=config.hearing.max_rework_rounds,
        max_total_images=config.hearing.max_total_images,
        max_total_output_tokens=config.hearing.max_total_output_tokens,
        hearing_prompt_bundle_sha256=FROZEN_M4_PROMPT_BUNDLE_SHA256,
        prosecutor_model_manifest_id=manifest.models["prosecutor"].model_manifest_id,
        defender_model_manifest_id=manifest.models["defender"].model_manifest_id,
        judge_model_manifest_id=manifest.models["judge"].model_manifest_id,
        manifest_id=manifest.manifest_id,
    )
    retrieval = _retrieval(session, pack, config, manifest)
    return Scenario(
        config=config,
        manifest=manifest,
        pack=pack,
        authority=derive_evidence_authority(pack),
        session=session,
        retrieval=retrieval,
        scope=_scope(session, retrieval),
        catalog=_catalog(),
    )


def _prepare(
    scenario: Scenario,
    role: VlmRole,
    *,
    grant=None,
    budget_usage: HearingBudgetUsage | None = None,
    prosecutor_output: HearingRoleOutput | None = None,
    defender_output: HearingRoleOutput | None = None,
    generation: HearingRequestGeneration | None = None,
) -> PreparedHearingRequest:
    return prepare_primary_hearing_request(
        role=role,
        session=scenario.session,
        cycle_scope=scenario.scope,
        retrieval=scenario.retrieval,
        evidence_pack=scenario.pack,
        evidence_authority=scenario.authority,
        hearing_grant=grant,
        budget_usage=budget_usage or HearingBudgetUsage(),
        config=scenario.config,
        run_manifest=scenario.manifest,
        catalog=scenario.catalog,
        prosecutor_output=prosecutor_output,
        defender_output=defender_output,
        generation=generation,
    )


def _role_output(
    scenario: Scenario,
    prepared: PreparedHearingRequest,
    *,
    prosecutor_output_id: str | None = None,
) -> HearingRoleOutput:
    crop_ref = next(
        ref for ref in prepared.request.allowed_evidence_refs if ref.kind == ArtifactKind.CROP
    )
    if prepared.request.role == VlmRole.PROSECUTOR:
        payload = ProsecutorModelPayload(
            arguments=(
                Argument(
                    stance=ArgumentStance.PROSECUTION,
                    claim="The selected crop supports the allegation.",
                    evidence_refs=(crop_ref,),
                    uncertainty=0.1,
                ),
            ),
            case_summary="The prosecution relies on the disclosed crop.",
        )
    else:
        payload = DefenderModelPayload(
            arguments=(
                Argument(
                    stance=ArgumentStance.DEFENSE,
                    claim="Occlusion remains a plausible counter-explanation.",
                    evidence_refs=(crop_ref,),
                    uncertainty=0.4,
                ),
            ),
            case_summary="The defense preserves observation uncertainty.",
        )
    return HearingRoleOutput(
        run_id=scenario.pack.run_id,
        case_id=scenario.pack.case_id,
        hearing_session_id=scenario.session.session_id,
        round_index=scenario.scope.cycle_index,
        prior_acquisition_rounds=scenario.scope.prior_acquisition_rounds,
        prior_rework_rounds=scenario.scope.prior_rework_rounds,
        current_evidence_pack_id=scenario.pack.pack_id,
        current_evidence_pack_version=scenario.pack.version,
        prompt_manifest=prepared.request.prompt_manifest,
        model_manifest_id=prepared.request.model_manifest_id,
        request_ref=ArtifactRef(
            kind=ArtifactKind.MODEL_REQUEST,
            artifact_id=prepared.request.request_id,
        ),
        response_ref=_ref(
            ArtifactKind.MODEL_RESPONSE,
            f"response-{prepared.request.role.value}",
        ),
        parse_receipt_ref=_ref(
            ArtifactKind.MODEL_PARSE_RECEIPT,
            f"parse-{prepared.request.role.value}",
        ),
        prosecutor_output_id=prosecutor_output_id,
        precedent_retrieval_degraded=False,
        precedent_retrieval_receipt_id=scenario.retrieval.receipt_id,
        precedent_retrieval_receipt_sha256=scenario.retrieval.receipt_sha256,
        payload=payload,
        manifest_id=scenario.manifest.manifest_id,
    )


def _assert_code(
    code: HearingRequestPreparationErrorCode,
    call,
) -> None:
    with pytest.raises(HearingRequestPreparationError) as captured:
        call()
    assert captured.value.reason_code == code


def test_three_roles_bind_exact_profiles_upstreams_and_one_crop() -> None:
    scenario = _scenario()
    prosecutor = _prepare(scenario, VlmRole.PROSECUTOR)
    prosecutor_output = _role_output(scenario, prosecutor)
    defender = _prepare(
        scenario,
        VlmRole.DEFENDER,
        grant=prosecutor.hearing_grant,
        budget_usage=HearingBudgetUsage(reserved_images=1),
        prosecutor_output=prosecutor_output,
    )
    defender_output = _role_output(
        scenario,
        defender,
        prosecutor_output_id=prosecutor_output.output_id,
    )
    judge = _prepare(
        scenario,
        VlmRole.JUDGE,
        grant=defender.hearing_grant,
        budget_usage=HearingBudgetUsage(reserved_images=2),
        prosecutor_output=prosecutor_output,
        defender_output=defender_output,
    )

    prepared = (prosecutor, defender, judge)
    assert tuple(item.request.provider_profile for item in prepared) == (
        scenario.config.hearing.prosecutor_profile,
        scenario.config.hearing.defender_profile,
        scenario.config.hearing.judge_profile,
    )
    assert all(len(item.request.media) == 1 for item in prepared)
    assert all(item.request.budget.max_images == 1 for item in prepared)
    assert all(
        {
            ref.artifact_id
            for ref in item.request.allowed_evidence_refs
            if ref.kind == ArtifactKind.CROP
        }
        == {item.request.media[0].crop_id}
        for item in prepared
    )
    assert defender.request.prosecutor_output_ref == ArtifactRef(
        kind=ArtifactKind.PARSED_MODEL_OUTPUT,
        artifact_id=prosecutor_output.output_id,
    )
    assert judge.request.defender_output_ref == ArtifactRef(
        kind=ArtifactKind.PARSED_MODEL_OUTPUT,
        artifact_id=defender_output.output_id,
    )
    assert defender.canonical_inputs.prosecutor_output_json == canonical_json(
        prosecutor_output.model_dump(mode="json")
    )
    assert judge.canonical_inputs.defender_output_json == canonical_json(
        defender_output.model_dump(mode="json")
    )


def test_m8_v2_context_advertises_real_acquisition_capabilities_without_mutating_v1() -> None:
    frozen = _scenario()
    frozen_context = json.loads(
        _prepare(frozen, VlmRole.PROSECUTOR).canonical_inputs.hearing_context_json
    )
    assert frozen_context["schema_version"] == "m4-hearing-prompt-context-v1"
    assert "acquisition_capabilities" not in frozen_context

    session = frozen.session.model_copy(
        update={
            "hearing_prompt_bundle_sha256": M8_HEARING_PROMPT_V2_BUNDLE_SHA256,
        }
    )
    retrieval = _retrieval(
        session,
        frozen.pack,
        frozen.config,
        frozen.manifest,
    )
    current = Scenario(
        config=frozen.config,
        manifest=frozen.manifest,
        pack=frozen.pack,
        authority=frozen.authority,
        session=session,
        retrieval=retrieval,
        scope=_scope(session, retrieval),
        catalog=_catalog(m8_v2=True),
    )

    current_context = json.loads(
        _prepare(current, VlmRole.PROSECUTOR).canonical_inputs.hearing_context_json
    )
    assert current_context["schema_version"] == "m8-hearing-prompt-context-v2"
    assert current_context["acquisition_capabilities"] == {
        "OTHER_CAMERA_SAME_TIME": "TOOL_UNAVAILABLE",
        "RECROP": "AVAILABLE",
        "REDETECT_HIGH_RES": "AVAILABLE",
        "REQUEST_MORE_FRAMES": "AVAILABLE",
        "TRACK_CONFIDENCE_CURVE": "AVAILABLE",
    }


def test_one_crop_per_role_fits_all_five_cycles_inside_twenty_image_budget() -> None:
    scenario = _scenario()
    required = 3 * scenario.session.max_total_judge_cycles
    assert required == 15 < scenario.session.max_total_images
    for reserved_images in range(required):
        prepared = _prepare(
            scenario,
            VlmRole.PROSECUTOR,
            budget_usage=HearingBudgetUsage(reserved_images=reserved_images),
        )
        assert prepared.request.budget.max_images == 1
    _assert_code(
        HearingRequestPreparationErrorCode.IMAGE_BUDGET_EXHAUSTED,
        lambda: _prepare(
            scenario,
            VlmRole.PROSECUTOR,
            budget_usage=HearingBudgetUsage(reserved_images=scenario.session.max_total_images),
        ),
    )


def test_absence_roles_receive_every_authoritative_clear_crop_and_full_budget() -> None:
    scenario = _scenario(absence=True)
    prosecutor = _prepare(scenario, VlmRole.PROSECUTOR)
    prosecutor_output = _role_output(scenario, prosecutor)
    defender = _prepare(
        scenario,
        VlmRole.DEFENDER,
        grant=prosecutor.hearing_grant,
        budget_usage=HearingBudgetUsage(reserved_images=3),
        prosecutor_output=prosecutor_output,
    )
    defender_output = _role_output(
        scenario,
        defender,
        prosecutor_output_id=prosecutor_output.output_id,
    )
    judge = _prepare(
        scenario,
        VlmRole.JUDGE,
        grant=defender.hearing_grant,
        budget_usage=HearingBudgetUsage(reserved_images=6),
        prosecutor_output=prosecutor_output,
        defender_output=defender_output,
    )

    assert scenario.pack.observation_sufficiency_input is not None
    expected = set(scenario.pack.observation_sufficiency_input.clear_crop_ids)
    for prepared in (prosecutor, defender, judge):
        assert len(prepared.request.media) == 3
        assert prepared.request.budget.max_images == 3
        assert prepared.request.budget.max_input_pixels == 30_000
        assert {item.crop_id for item in prepared.request.media} == expected

    _assert_code(
        HearingRequestPreparationErrorCode.IMAGE_BUDGET_EXHAUSTED,
        lambda: _prepare(
            scenario,
            VlmRole.PROSECUTOR,
            budget_usage=HearingBudgetUsage(reserved_images=18),
        ),
    )


def test_latest_acquisition_crop_has_priority_over_stable_old_crop(monkeypatch) -> None:
    initial = _scenario()
    first = _prepare(initial, VlmRole.PROSECUTOR)
    monkeypatch.setattr(
        evidence_helpers,
        "SESSION_ID",
        initial.session.session_id,
    )
    execution = evidence_helpers._execution(
        initial.pack,
        AcquisitionAction.RECROP,
    )
    update = evidence_helpers._finalize(initial.pack, execution)
    retrieval = _retrieval(
        initial.session,
        update.pack,
        initial.config,
        initial.manifest,
        cycle_index=2,
        prior_acquisitions=1,
    )
    scenario = Scenario(
        config=initial.config,
        manifest=initial.manifest,
        pack=update.pack,
        authority=update.authority,
        session=initial.session,
        retrieval=retrieval,
        scope=_scope(initial.session, retrieval),
        catalog=initial.catalog,
    )
    prepared = _prepare(
        scenario,
        VlmRole.PROSECUTOR,
        grant=first.hearing_grant,
        budget_usage=HearingBudgetUsage(reserved_images=3),
    )
    new_crop_id = next(
        ref.artifact_id
        for ref in update.receipt.tool_result.output_refs
        if ref.kind == ArtifactKind.CROP
    )
    assert prepared.request.media[0].crop_id == new_crop_id


def test_external_provider_rejects_local_only_media_without_fallback() -> None:
    scenario = _scenario(external_prosecutor=True)
    _assert_code(
        HearingRequestPreparationErrorCode.PRIVACY_POLICY_VIOLATION,
        lambda: _prepare(scenario, VlmRole.PROSECUTOR),
    )


def test_prompt_bundle_and_session_model_tamper_fail_closed() -> None:
    scenario = _scenario()
    changed_catalog = _catalog(changed_judge_schema=True)
    _assert_code(
        HearingRequestPreparationErrorCode.PROMPT_BUNDLE_MISMATCH,
        lambda: prepare_primary_hearing_request(
            role=VlmRole.PROSECUTOR,
            session=scenario.session,
            cycle_scope=scenario.scope,
            retrieval=scenario.retrieval,
            evidence_pack=scenario.pack,
            evidence_authority=scenario.authority,
            hearing_grant=None,
            budget_usage=HearingBudgetUsage(),
            config=scenario.config,
            run_manifest=scenario.manifest,
            catalog=changed_catalog,
        ),
    )

    tampered_session = scenario.session.model_copy(
        update={"prosecutor_model_manifest_id": "f" * 64}
    )
    retrieval = _retrieval(
        tampered_session,
        scenario.pack,
        scenario.config,
        scenario.manifest,
    )
    _assert_code(
        HearingRequestPreparationErrorCode.MODEL_MANIFEST_MISMATCH,
        lambda: prepare_primary_hearing_request(
            role=VlmRole.PROSECUTOR,
            session=tampered_session,
            cycle_scope=_scope(tampered_session, retrieval),
            retrieval=retrieval,
            evidence_pack=scenario.pack,
            evidence_authority=scenario.authority,
            hearing_grant=None,
            budget_usage=HearingBudgetUsage(),
            config=scenario.config,
            run_manifest=scenario.manifest,
            catalog=scenario.catalog,
        ),
    )


def test_budget_boundaries_and_backlog_generation_are_strict() -> None:
    scenario = _scenario()
    boundary = _prepare(
        scenario,
        VlmRole.PROSECUTOR,
        budget_usage=HearingBudgetUsage(accounted_output_tokens=5_999),
        generation=HearingRequestGeneration(
            retry_generation=2,
            backlog_item_id=_sha("backlog"),
        ),
    )
    assert boundary.request.budget.max_output_tokens == 1
    assert boundary.request.backlog_retry_context is not None
    assert boundary.request.backlog_retry_context.retry_generation == 2
    _assert_code(
        HearingRequestPreparationErrorCode.OUTPUT_TOKEN_BUDGET_EXHAUSTED,
        lambda: _prepare(
            scenario,
            VlmRole.PROSECUTOR,
            budget_usage=HearingBudgetUsage(accounted_output_tokens=6_000),
        ),
    )
    _assert_code(
        HearingRequestPreparationErrorCode.BACKLOG_GENERATION_INVALID,
        lambda: HearingRequestGeneration(
            retry_generation=0,
            backlog_item_id=_sha("forbidden-backlog"),
        ),
    )

    pixel_limited = _scenario(max_input_pixels=19_999)
    _assert_code(
        HearingRequestPreparationErrorCode.INPUT_PIXEL_BUDGET_EXCEEDED,
        lambda: _prepare(pixel_limited, VlmRole.PROSECUTOR),
    )
    prompt_limited = _scenario(max_prompt_bytes=128)
    _assert_code(
        HearingRequestPreparationErrorCode.PROMPT_BUDGET_EXCEEDED,
        lambda: _prepare(prompt_limited, VlmRole.PROSECUTOR),
    )


def _response(
    request,
    raw_response: bytes,
) -> HearingModelResponse:
    content_sha256 = hashlib.sha256(raw_response).hexdigest()
    response_id = derive_hearing_model_response_id(
        request.run_id,
        request.request_id,
        content_sha256,
    )
    return HearingModelResponse(
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
        content_sha256=content_sha256,
        size_bytes=len(raw_response),
        model_manifest_id=request.model_manifest_id,
        manifest_id=request.manifest_id,
    )


def test_repair_is_media_free_and_preserves_scope_whitelists_and_generation() -> None:
    scenario = _scenario()
    original = _prepare(
        scenario,
        VlmRole.PROSECUTOR,
        generation=HearingRequestGeneration(
            retry_generation=1,
            backlog_item_id=_sha("repair-backlog"),
        ),
    )
    raw_response = b'{"role":"PROSECUTOR"}'
    response = _response(original.request, raw_response)
    inspection = inspect_hearing_response(
        raw_response,
        request=original.request,
        response=response,
    )
    repaired = prepare_hearing_repair_request(
        original=original,
        response=response,
        inspection=inspection,
        raw_response=raw_response,
        session=scenario.session,
        cycle_scope=scenario.scope,
        budget_usage=HearingBudgetUsage(
            reserved_images=1,
            accounted_output_tokens=20,
        ),
        config=scenario.config,
        run_manifest=scenario.manifest,
        catalog=scenario.catalog,
    )

    assert repaired.request.attempt_index == 1
    assert repaired.request.media == ()
    assert repaired.request.budget.max_images == 0
    assert repaired.request.budget.max_input_pixels == 0
    assert repaired.request.allowed_evidence_refs == original.request.allowed_evidence_refs
    assert repaired.request.allowed_precedent_refs == original.request.allowed_precedent_refs
    assert repaired.request.cycle_scope_id == original.request.cycle_scope_id
    assert repaired.request.hearing_context_sha256 == original.request.hearing_context_sha256
    assert repaired.request.provider_profile == original.request.provider_profile
    assert repaired.request.prompt_manifest.prompt_id == original.request.prompt_manifest.prompt_id
    assert repaired.request.backlog_retry_context == original.request.backlog_retry_context
    assert repaired.hearing_grant == original.hearing_grant
    assert repaired.disclosure is None
    prior = json.loads(repaired.canonical_inputs.prior_response_json)
    assert prior["encoding"] == "utf-8"
    assert prior["text"] == raw_response.decode("utf-8")
    result = finalize_hearing_parse(
        inspection,
        repair_request_id=repaired.request.request_id,
    )
    assert result.receipt.repair_request_id == repaired.request.request_id


def test_canonical_primary_request_identity_is_golden() -> None:
    scenario = _scenario()
    prepared = _prepare(scenario, VlmRole.PROSECUTOR)

    assert (
        prepared.request.hearing_context_sha256
        == hashlib.sha256(
            prepared.canonical_inputs.hearing_context_json.encode("utf-8")
        ).hexdigest()
    )
    assert (
        canonical_json(json.loads(prepared.canonical_inputs.hearing_context_json))
        == prepared.canonical_inputs.hearing_context_json
    )
    assert prepared.request.hearing_context_sha256 == (
        "bfbe701292c527dbdf181537931ccc86aa251def8e607943d94fd733b860a75f"
    )
    assert prepared.request.request_id == (
        "0543fcdbdf1231405e37770387cc2ac2bf81037c43d0c06c6f8d54cda50a30bb"
    )
