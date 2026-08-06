from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from labcourt.adapters.jinja_prompt_renderer import PROMPT_DEFINITIONS, JinjaPromptCatalog
from labcourt.adapters.vlm.openai_compatible import ImmutableRenderedPromptRegistry
from labcourt.application.screening_request import (
    FROZEN_M3_PROMPT_BUNDLE_SHA256,
    SCREENING_ABSENCE_PROMPT_ID,
    SCREENING_PRESENCE_PROMPT_ID,
    prepare_screening_request,
)
from labcourt.config_loader import load_config
from labcourt.contracts.backlog import BacklogRetryContext
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.config import AppConfig
from labcourt.contracts.detections import Keypoint
from labcourt.contracts.enums import (
    AnchorType,
    ArtifactKind,
    AssociationMethod,
    CropSource,
    EvidenceClass,
    ExecutionLocation,
    MediaAccess,
    MediaAvailability,
    MediaType,
    ObservationSource,
    PpeType,
    PrivacyPolicy,
    PrivacyReasonCode,
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
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.storage import ArtifactRef, ClosureReport
from labcourt.exceptions import (
    BudgetExceeded,
    ContractViolation,
    EvidenceMissing,
    ManifestMismatch,
    PrivacyPolicyViolation,
)
from labcourt.schema_export import expected_schema_files
from labcourt.services.m3 import build_screening_prompt_catalog

ROOT = Path(__file__).parents[2]
FIXTURES = ROOT / "tests" / "fixtures" / "m2"
RUN_ID = "run-01"


def _base_config() -> AppConfig:
    return load_config(ROOT / "configs" / "demo.yaml")


def _config_with(
    *,
    max_images: int | None = None,
    max_input_pixels: int | None = None,
    max_prompt_bytes: int | None = None,
    external: bool = False,
) -> AppConfig:
    payload = _base_config().model_dump(mode="json", exclude={"config_sha256"})
    screening = payload["screening"]
    assert isinstance(screening, dict)
    if max_images is not None:
        screening["max_images"] = max_images
    if max_input_pixels is not None:
        screening["max_input_pixels"] = max_input_pixels
    if max_prompt_bytes is not None:
        screening["max_prompt_bytes"] = max_prompt_bytes
    if external:
        providers = payload["providers"]
        assert isinstance(providers, dict)
        providers["fake-screening"] = {
            "provider": "remote-fixture",
            "model": "remote-screening",
            "revision": "2026-07-28",
            "quantization": "int8",
            "execution_location": "EXTERNAL",
            "transport": "HTTP",
            "allow_full_frame": False,
            "endpoint_env": "LABCOURT_TEST_ENDPOINT",
            "api_key_env": "LABCOURT_TEST_API_KEY",
            "timeout_seconds": 15.0,
            "cache_enabled": True,
            "pricing_currency": "USD",
            "input_cost_per_million_tokens": 2.5,
            "output_cost_per_million_tokens": 10.0,
        }
    return AppConfig.model_validate(payload)


def _manifest(config: AppConfig | None = None) -> RunManifest:
    manifest = RunManifest.model_validate_json(
        (FIXTURES / "run-manifest-fake.json").read_text(encoding="utf-8")
    )
    if config is None or config.config_sha256 == manifest.config_sha256:
        return manifest

    payload = manifest.model_dump(mode="json", exclude={"manifest_id"})
    payload["config_sha256"] = config.config_sha256
    models = payload["models"]
    assert isinstance(models, dict)
    screening_model = models["screening"]
    assert isinstance(screening_model, dict)
    profile = config.providers[config.screening.provider_profile]
    screening_model.pop("model_manifest_id", None)
    screening_model.update(
        {
            "provider": profile.provider,
            "model": profile.model,
            "revision": profile.revision,
            "quantization": profile.quantization,
        }
    )
    return RunManifest.model_validate(payload)


def _event(evidence_class: EvidenceClass, manifest: RunManifest) -> CandidateEvent:
    filename = (
        "candidate-event-presence.json"
        if evidence_class == EvidenceClass.PRESENCE
        else "candidate-event-absence-strict.json"
    )
    payload = json.loads((FIXTURES / filename).read_text(encoding="utf-8"))
    payload.pop("event_id", None)
    payload["manifest_id"] = manifest.manifest_id
    return CandidateEvent.model_validate(payload)


def _presence_crop(
    event: CandidateEvent,
    *,
    frame_index: int,
    token: str,
    media_access: MediaAccess = MediaAccess.LOCAL_ONLY,
) -> Crop:
    frame_id = f"{event.camera_id}:{event.stream_id}:{frame_index}"
    frame_ref = ArtifactRef(kind=ArtifactKind.FRAME, artifact_id=frame_id)
    detection_ref = ArtifactRef(kind=ArtifactKind.DETECTION, artifact_id=f"det-{token}")
    source_refs = tuple(sorted((detection_ref, frame_ref), key=lambda ref: ref.sort_key))
    source_sha = sha256_hex(["source", token])
    pixel_sha = sha256_hex(["pixel", token])
    media_sha = sha256_hex(["media", token])
    return Crop(
        frame_id=frame_id,
        source=CropSource.DETECTION_FOCUS,
        bbox=BBoxXYXY(x1=10, y1=20, x2=110, y2=220),
        source_refs=source_refs,
        local_path=f"{RUN_ID}/frames/{media_sha}.png",
        availability=MediaAvailability.AVAILABLE,
        source_media_sha256=source_sha,
        pixel_sha256=pixel_sha,
        media_sha256=media_sha,
        output_width=100,
        output_height=200,
        size_bytes=1_024,
        media_type=MediaType.IMAGE_PNG,
        encoding_version="png-v1",
        privacy_receipt=PrivacyReceipt(
            policy=PrivacyPolicy.FULL_REDACTION,
            transform_version="ppe-redaction-v1",
            media_access=media_access,
            reason_code=(
                PrivacyReasonCode.POLICY_LOCAL_ONLY
                if media_access == MediaAccess.LOCAL_ONLY
                else PrivacyReasonCode.SUBJECT_FULL_REDACTION
            ),
            input_refs=source_refs,
            fill_rgb=(0, 0, 0),
        ),
        primary_track_ref=event.primary_track_ref,
        tags={"zone_id": event.zone_id},
    )


def _panorama_crop(event: CandidateEvent, *, frame_index: int) -> Crop:
    frame_id = f"{event.camera_id}:{event.stream_id}:{frame_index}"
    frame_ref = ArtifactRef(kind=ArtifactKind.FRAME, artifact_id=frame_id)
    media_sha = sha256_hex(["panorama-media", frame_id])
    return Crop(
        frame_id=frame_id,
        source=CropSource.PANORAMA,
        bbox=BBoxXYXY(x1=0, y1=0, x2=100, y2=100),
        panorama_long_edge_limit=100,
        source_refs=(frame_ref,),
        local_path=f"{RUN_ID}/frames/{media_sha}.png",
        availability=MediaAvailability.AVAILABLE,
        source_media_sha256=sha256_hex(["panorama-source", frame_id]),
        pixel_sha256=sha256_hex(["panorama-pixel", frame_id]),
        media_sha256=media_sha,
        output_width=100,
        output_height=100,
        size_bytes=1_024,
        media_type=MediaType.IMAGE_PNG,
        encoding_version="png-v1",
        privacy_receipt=PrivacyReceipt(
            policy=PrivacyPolicy.FULL_REDACTION,
            transform_version="ppe-redaction-v1",
            media_access=MediaAccess.LOCAL_ONLY,
            reason_code=PrivacyReasonCode.PANORAMA_FULL_REDACTION,
            input_refs=(frame_ref,),
            fill_rgb=(0, 0, 0),
        ),
        tags={"zone_id": event.zone_id},
    )


def _absence_crop(event: CandidateEvent, *, frame_index: int) -> Crop:
    frame_id = f"{event.camera_id}:{event.stream_id}:{frame_index}"
    frame_ref = ArtifactRef(kind=ArtifactKind.FRAME, artifact_id=frame_id)
    media_sha = sha256_hex(["absence-media", frame_id])
    preserved = BBoxXYXY(x1=10, y1=10, x2=90, y2=55)
    return Crop(
        frame_id=frame_id,
        source=CropSource.ANCHOR_FOCUS,
        bbox=BBoxXYXY(x1=0, y1=0, x2=100, y2=100),
        source_refs=(frame_ref,),
        local_path=f"{RUN_ID}/frames/{media_sha}.png",
        availability=MediaAvailability.AVAILABLE,
        source_media_sha256=sha256_hex(["absence-source", frame_id]),
        pixel_sha256=sha256_hex(["absence-pixel", frame_id]),
        media_sha256=media_sha,
        output_width=100,
        output_height=100,
        size_bytes=1_024,
        media_type=MediaType.IMAGE_PNG,
        encoding_version="png-v1",
        privacy_receipt=PrivacyReceipt(
            policy=PrivacyPolicy.PPE_PRESERVING_REDACTION,
            transform_version="ppe-redaction-v1",
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


def _close(draft: EvidencePackDraft) -> EvidencePack:
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


def _presence_pack(
    manifest: RunManifest,
    *,
    crop_count: int = 1,
    include_panorama: bool = False,
    media_accesses: tuple[MediaAccess, ...] | None = None,
) -> EvidencePack:
    event = _event(EvidenceClass.PRESENCE, manifest)
    frame_indexes = tuple(range(91 - crop_count, 91))
    accesses = media_accesses or tuple(MediaAccess.LOCAL_ONLY for _ in frame_indexes)
    crops = tuple(
        _presence_crop(event, frame_index=index, token=f"{index}-{ordinal}", media_access=access)
        for ordinal, (index, access) in enumerate(zip(frame_indexes, accesses, strict=True))
    )
    panoramas = (
        (_panorama_crop(event, frame_index=event.trigger_frame),) if include_panorama else ()
    )
    key_indexes = tuple(sorted(set((*frame_indexes, event.trigger_frame))))
    return _close(
        EvidencePackDraft(
            run_id=RUN_ID,
            case_id=derive_case_id(event.event_id),
            version=1,
            event=event,
            key_frame_ids=tuple(
                f"{event.camera_id}:{event.stream_id}:{index}" for index in key_indexes
            ),
            panorama_crops=panoramas,
            focus_crops=crops,
            objective_facts=event.objective_facts,
            track_summary=TrackSummary(
                primary_track_ref=event.primary_track_ref,
                start_frame=0,
                end_frame_exclusive=91,
                observed_frame_count=91,
            ),
            confirmation_record=event.confirmation,
            manifest_id=manifest.manifest_id,
        )
    )


def _absence_pack(manifest: RunManifest) -> EvidencePack:
    event = _event(EvidenceClass.ABSENCE, manifest)
    temporal = tuple(_absence_crop(event, frame_index=index) for index in (0, 75, 149))
    clear_ids = tuple(sorted(crop.crop_id for crop in temporal))
    return _close(
        EvidencePackDraft(
            run_id=RUN_ID,
            case_id=derive_case_id(event.event_id),
            version=1,
            event=event,
            key_frame_ids=tuple(
                f"{event.camera_id}:{event.stream_id}:{index}" for index in (0, 75, 149, 150, 151)
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
            manifest_id=manifest.manifest_id,
        )
    )


def _prompt_json(text: str, name: str) -> object:
    prefix = f"{name}="
    line = next(line for line in text.splitlines() if line.startswith(prefix))
    return json.loads(line.removeprefix(prefix))


def test_production_catalog_uses_frozen_bundle_and_exact_exported_schema() -> None:
    manifest = _manifest()
    catalog = build_screening_prompt_catalog(manifest)
    expected_schema = canonical_json(
        json.loads(expected_schema_files()["screening-model-payload.schema.json"])
    )
    expected_schema_sha = hashlib.sha256(expected_schema.encode("utf-8")).hexdigest()

    assert catalog.bundle_sha256 == FROZEN_M3_PROMPT_BUNDLE_SHA256
    assert {
        catalog.manifest(definition.prompt_id).output_schema_sha256
        for definition in PROMPT_DEFINITIONS
    } == {expected_schema_sha}

    wrong_bundle = manifest.model_copy(update={"prompt_bundle_sha256": "0" * 64})
    with pytest.raises(ManifestMismatch, match="frozen M3 prompt bundle"):
        build_screening_prompt_catalog(wrong_bundle)


def test_presence_request_is_reproducible_whitelisted_and_registry_ready() -> None:
    config = _base_config()
    manifest = _manifest()
    pack = _presence_pack(manifest, include_panorama=True)
    catalog = build_screening_prompt_catalog(manifest)

    first = prepare_screening_request(pack, config, manifest, catalog)
    second = prepare_screening_request(pack, config, manifest, catalog)
    request = first.request

    assert first == second
    assert request.prompt_manifest.prompt_id == SCREENING_PRESENCE_PROMPT_ID
    assert request.manifest_id == manifest.manifest_id
    assert request.model_manifest_id == manifest.models["screening"].model_manifest_id
    assert request.objective_summary == {"duration_frames": 91}
    assert tuple(item.source for item in request.media) == (CropSource.DETECTION_FOCUS,)
    assert request.budget.max_images == config.screening.max_images
    assert request.budget.timeout_seconds == config.screening.timeout_seconds
    assert request.budget.claim_completion_grace_seconds == 5.0
    assert request.budget.claim_lease_seconds == (
        config.screening.timeout_seconds + request.budget.claim_completion_grace_seconds
    )
    assert request.budget.pricing_currency == "USD"
    assert request.budget.input_cost_per_million_tokens == 0.0
    assert request.budget.output_cost_per_million_tokens == 0.0
    assert request.budget.max_estimated_cost == config.screening.max_estimated_cost
    crop_refs = tuple(ref for ref in request.allowed_evidence_refs if ref.kind == ArtifactKind.CROP)
    assert tuple(ref.artifact_id for ref in crop_refs) == request.allowed_crop_ids
    assert any(ref.kind == ArtifactKind.FRAME for ref in request.allowed_evidence_refs)
    assert any(ref.kind == ArtifactKind.OBJECTIVE_FACT for ref in request.allowed_evidence_refs)

    registry = ImmutableRenderedPromptRegistry((first.rendered_prompt,))
    assert registry.resolve(request) == first.rendered_prompt.utf8_bytes

    evidence = _prompt_json(first.rendered_prompt.text, "EVIDENCE_JSON")
    rules = _prompt_json(first.rendered_prompt.text, "RULES_JSON")
    assert isinstance(evidence, dict)
    assert isinstance(rules, dict)
    assert rules["violation_type"] == pack.event.violation_type.value
    assert "local_path" not in first.rendered_prompt.text
    assert "api_key_env" not in first.rendered_prompt.text
    assert "endpoint_env" not in first.rendered_prompt.text
    assert all(crop.local_path not in first.rendered_prompt.text for crop in pack.crops)


def test_retry_context_changes_request_identity_without_changing_prompt_bytes() -> None:
    config = _base_config()
    manifest = _manifest()
    pack = _presence_pack(manifest, include_panorama=True)
    catalog = build_screening_prompt_catalog(manifest)
    direct = prepare_screening_request(pack, config, manifest, catalog)
    context = BacklogRetryContext(
        backlog_item_id="9" * 64,
        retry_generation=2,
    )

    retry = prepare_screening_request(
        pack,
        config,
        manifest,
        catalog,
        backlog_retry_context=context,
    )

    assert retry.request.backlog_retry_context == context
    assert retry.request.request_id != direct.request.request_id
    assert retry.request.cache_key != direct.request.cache_key
    assert retry.rendered_prompt == direct.rendered_prompt


def test_absence_request_uses_absence_prompt_and_pack_observation_authority() -> None:
    config = _base_config()
    manifest = _manifest()
    pack = _absence_pack(manifest)
    prepared = prepare_screening_request(
        pack,
        config,
        manifest,
        build_screening_prompt_catalog(manifest),
    )

    assert prepared.request.prompt_manifest.prompt_id == SCREENING_ABSENCE_PROMPT_ID
    assert prepared.request.evidence_class == EvidenceClass.ABSENCE
    evidence = _prompt_json(prepared.rendered_prompt.text, "EVIDENCE_JSON")
    assert isinstance(evidence, dict)
    authority = evidence["observation_sufficiency"]
    assert isinstance(authority, dict)
    assert authority["authoritative_clear_crop_ids"] == sorted(
        pack.observation_sufficiency_input.clear_crop_ids  # type: ignore[union-attr]
    )
    assert authority["required_clear_count"] == 2
    assert evidence["confirmation"]["post_threshold_recovery_frame_id"].endswith(":151")


def test_external_request_discloses_only_cloud_allowed_non_panorama_media() -> None:
    config = _config_with(external=True)
    manifest = _manifest(config)
    pack = _presence_pack(
        manifest,
        crop_count=2,
        include_panorama=True,
        media_accesses=(MediaAccess.LOCAL_ONLY, MediaAccess.CLOUD_ALLOWED),
    )

    prepared = prepare_screening_request(
        pack,
        config,
        manifest,
        build_screening_prompt_catalog(manifest),
    )

    assert prepared.request.execution_location == ExecutionLocation.EXTERNAL
    assert len(prepared.request.media) == 1
    assert prepared.request.media[0].media_access == MediaAccess.CLOUD_ALLOWED
    assert prepared.request.media[0].source != CropSource.PANORAMA
    assert {
        ref.artifact_id
        for ref in prepared.request.allowed_evidence_refs
        if ref.kind == ArtifactKind.CROP
    } == set(prepared.request.allowed_crop_ids)


@settings(max_examples=8, deadline=None)
@given(max_images=st.integers(min_value=1, max_value=3))
def test_image_budget_is_exact_and_never_silently_truncates(max_images: int) -> None:
    config = _config_with(max_images=max_images)
    manifest = _manifest(config)
    pack = _presence_pack(manifest, crop_count=2)
    catalog = build_screening_prompt_catalog(manifest)

    if max_images < 2:
        with pytest.raises(BudgetExceeded, match="image budget"):
            prepare_screening_request(pack, config, manifest, catalog)
    else:
        request = prepare_screening_request(pack, config, manifest, catalog).request
        assert len(request.media) == 2
        assert request.budget.max_images == max_images


def test_pixel_budget_and_unavailable_media_fail_closed() -> None:
    config = _config_with(max_input_pixels=39_999)
    manifest = _manifest(config)
    pack = _presence_pack(manifest, crop_count=2)
    with pytest.raises(BudgetExceeded, match="input budget"):
        prepare_screening_request(
            pack,
            config,
            manifest,
            build_screening_prompt_catalog(manifest),
        )

    base_manifest = _manifest()
    unavailable = _presence_pack(base_manifest)
    crop = unavailable.focus_crops[0].model_copy(update={"availability": MediaAvailability.PURGING})
    payload = unavailable.model_dump(
        mode="json", exclude={"pack_id", "closure_report", "focus_crops"}
    )
    payload["focus_crops"] = [crop.model_dump(mode="json")]
    draft = EvidencePackDraft.model_validate(payload)
    unavailable = _close(draft)
    with pytest.raises(EvidenceMissing, match="no available crop"):
        prepare_screening_request(
            unavailable,
            _base_config(),
            base_manifest,
            build_screening_prompt_catalog(base_manifest),
        )


def test_rendered_prompt_byte_budget_is_exact_and_fails_before_request_creation() -> None:
    base_config = _base_config()
    base_manifest = _manifest()
    base_pack = _presence_pack(base_manifest, crop_count=2)
    prompt_size = len(
        prepare_screening_request(
            base_pack,
            base_config,
            base_manifest,
            build_screening_prompt_catalog(base_manifest),
        ).rendered_prompt.utf8_bytes
    )

    exact_config = _config_with(max_prompt_bytes=prompt_size)
    exact_manifest = _manifest(exact_config)
    exact = prepare_screening_request(
        _presence_pack(exact_manifest, crop_count=2),
        exact_config,
        exact_manifest,
        build_screening_prompt_catalog(exact_manifest),
    )
    assert len(exact.rendered_prompt.utf8_bytes) == prompt_size
    assert exact.request.budget.max_prompt_bytes == prompt_size

    too_tight = _config_with(max_prompt_bytes=prompt_size - 1)
    too_tight_manifest = _manifest(too_tight)
    with pytest.raises(BudgetExceeded, match="prompt byte budget"):
        prepare_screening_request(
            _presence_pack(too_tight_manifest, crop_count=2),
            too_tight,
            too_tight_manifest,
            build_screening_prompt_catalog(too_tight_manifest),
        )


def test_policy_and_canonical_locator_fail_closed_without_fabricating_media() -> None:
    external_config = _config_with(external=True)
    external_manifest = _manifest(external_config)
    local_only_pack = _presence_pack(external_manifest)
    with pytest.raises(PrivacyPolicyViolation, match="privacy policy"):
        prepare_screening_request(
            local_only_pack,
            external_config,
            external_manifest,
            build_screening_prompt_catalog(external_manifest),
        )

    manifest = _manifest()
    noncanonical = _presence_pack(manifest)
    crop = noncanonical.focus_crops[0].model_copy(update={"local_path": "frames/alias.png"})
    payload = noncanonical.model_dump(
        mode="json", exclude={"pack_id", "closure_report", "focus_crops"}
    )
    payload["focus_crops"] = [crop.model_dump(mode="json")]
    draft = EvidencePackDraft.model_validate(payload)
    noncanonical = _close(draft)
    with pytest.raises(ContractViolation, match="canonical run media locator"):
        prepare_screening_request(
            noncanonical,
            _base_config(),
            manifest,
            build_screening_prompt_catalog(manifest),
        )


def test_manifest_profile_and_prompt_bundle_mismatches_are_rejected() -> None:
    config = _base_config()
    manifest = _manifest()
    pack = _presence_pack(manifest)
    catalog = build_screening_prompt_catalog(manifest)

    changed_config = _config_with(max_images=7)
    with pytest.raises(ManifestMismatch, match="config_sha256"):
        prepare_screening_request(pack, changed_config, manifest, catalog)

    wrong_model = manifest.models["screening"].model_copy(update={"model": "other-model"})
    wrong_manifest = manifest.model_copy(
        update={"models": {**manifest.models, "screening": wrong_model}}
    )
    with pytest.raises(ManifestMismatch, match=r"screening\.model"):
        prepare_screening_request(pack, config, wrong_manifest, catalog)

    schema_json = canonical_json({})
    wrong_catalog = JinjaPromptCatalog(
        output_schema_json_by_prompt={
            definition.prompt_id: schema_json for definition in PROMPT_DEFINITIONS
        }
    )
    with pytest.raises(ManifestMismatch, match="prompt_bundle_sha256"):
        prepare_screening_request(pack, config, manifest, wrong_catalog)
