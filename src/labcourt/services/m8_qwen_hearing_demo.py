"""Synthetic gray-zone preparation and one-shot Qwen hearing demonstration."""
# ruff: noqa: RUF001, E501

from __future__ import annotations

import hashlib
import json
import platform
import threading
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path
from typing import Any
from uuid import uuid4

from PIL import Image

from labcourt.adapters.m8_qwen_demo_acquisition import (
    M8_QWEN_DEMO_ACQUISITION_COMPONENT,
    M8_QWEN_DEMO_ACQUISITION_COMPONENT_KEY,
    M8QwenDemoSealedRecropExecutor,
)
from labcourt.adapters.pillow_media import encode_rgb_png
from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.adapters.storage.sqlite_repository import MigrationRunner, SQLiteEvidenceRepository
from labcourt.adapters.stored_png_verifier import StoredPngVerifier
from labcourt.adapters.vlm.http_transport import (
    OpenAICompatibleTransportConfigurationError,
    build_openai_compatible_transport,
)
from labcourt.adapters.vlm.openai_compatible import (
    OpenAICompatibleTransport,
    OpenAICompatibleTransportRequest,
    OpenAICompatibleTransportResponse,
)
from labcourt.application.m8_personal_demo_api import (
    M8_PERSONAL_DEMO_ROLE_TOKENS,
    assemble_m8_personal_demo_api,
)
from labcourt.application.screening_request import (
    FROZEN_M3_PROMPT_BUNDLE_SHA256,
    prepare_screening_request,
)
from labcourt.config_loader import load_config
from labcourt.contracts.canonical import canonical_bytes, canonical_json, sha256_hex
from labcourt.contracts.config import AppConfig, VlmProviderProfile
from labcourt.contracts.detections import Detection, Keypoint
from labcourt.contracts.enums import (
    AnchorType,
    ArtifactKind,
    AssociationMethod,
    CaseStatus,
    ConfirmationPolicy,
    CropSource,
    DeviceClass,
    EvidenceClass,
    MediaAccess,
    MediaAvailability,
    MediaType,
    ObjectiveFactKind,
    ObservationSource,
    OperatingSystemFamily,
    PpeType,
    PrivacyPolicy,
    PrivacyReasonCode,
    ScreeningDecision,
    ViolationType,
    VlmRole,
    WearStatus,
)
from labcourt.contracts.events import (
    CandidateEvent,
    ConfirmationRecord,
    ObjectiveFact,
    derive_case_id,
)
from labcourt.contracts.evidence import (
    Crop,
    EvidencePackDraft,
    ObservabilityComponents,
    ObservabilityScore,
    ObservationSufficiencyInput,
    PrivacyReceipt,
    TrackSummary,
)
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.m3_models import EvidenceCitation
from labcourt.contracts.m3_operations import (
    FakeVLMFixtureBundle,
    FakeVLMFixtureDisposition,
    FakeVLMResponseFixtureInput,
)
from labcourt.contracts.m8_hearing_api import (
    M8HearingEligibility,
    M8HearingL5Status,
    M8HearingModelMode,
    M8HearingProviderSelectionV1,
    M8HearingStartRequestV1,
    M8HearingViewV1,
)
from labcourt.contracts.m8_qwen_hearing_demo import (
    M8QwenHearingDemoAttemptOutcome,
    M8QwenHearingDemoAttemptReceiptV1,
    M8QwenHearingDemoDeliveryState,
    M8QwenHearingDemoEvidenceRole,
    M8QwenHearingDemoEvidenceV1,
    M8QwenHearingDemoPreparationV1,
    M8QwenHearingProviderReceiptV1,
)
from labcourt.contracts.manifests import (
    DecodingParameters,
    ModelManifest,
    PlatformSummary,
    RunManifest,
    SoftwareComponentManifest,
    StreamManifest,
)
from labcourt.contracts.screening import FrameObservation, ScreeningModelPayload
from labcourt.contracts.storage import ArtifactRef
from labcourt.contracts.verdicts import ObjectiveClaim
from labcourt.exceptions import ArtifactConflict
from labcourt.ports.pixels import rgb8_pixel_sha256
from labcourt.services.m3 import build_screening_prompt_catalog
from labcourt.services.m3_operations import open_m3_operations_service
from labcourt.services.m8_hearing_api import M8HearingApiService
from labcourt.services.m8_hearing_runtime import open_m8_hearing_runtime

QWEN_MODEL_SNAPSHOT = "qwen3.7-plus-2026-05-26"
QWEN_MODEL_REVISION = "2026-05-26"
QWEN_ENDPOINT_ENV = "LABCOURT_QWEN_ENDPOINT"
QWEN_API_KEY_ENV = "LABCOURT_QWEN_API_KEY"
QWEN_PROFILE_NAMES = ("qwen-prosecutor", "qwen-defender", "qwen-judge")
DEMO_STREAM_ID = "m8-qwen-synthetic"
DEMO_ZONE_ID = "hood-01"
DEMO_LOCATION_ID = "room-chem-301"
DEMO_WIDTH = 1024
DEMO_HEIGHT = 768
DEMO_RECORDED_AT = datetime(2026, 8, 13, 8, 0, tzinfo=UTC)

PRIMARY_IMAGE_PROMPT = (
    "Synthetic evidence image for a LabCourt demo: a clearly fictional, faceless 3D "
    "laboratory mannequin at a fume hood, wearing a lab coat and gloves; the eye area "
    "is partly hidden by a strong reflection and oblique angle so safety goggles cannot "
    "be determined. No text, logo, real person, injury, or enforcement implication."
)
SUPPLEMENTARY_IMAGE_PROMPT = (
    "Pre-authorized synthetic supplementary evidence of the same fictional faceless 3D "
    "laboratory mannequin from a different close oblique angle; glare and hood-frame "
    "occlusion still make protective eyewear ambiguous. No text, logo, or real person."
)


def _now() -> datetime:
    return datetime.now(UTC)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _artifact_bytes(value: object) -> bytes:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    return (canonical_json(value) + "\n").encode("utf-8")


def _write_equal_or_new(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != data:
            raise ArtifactConflict("TARGET_ALREADY_EXISTS")
        return
    path.write_bytes(data)


def _model(component: str, profile: VlmProviderProfile) -> ModelManifest:
    return ModelManifest(
        component=component,
        provider=profile.provider,
        model=profile.model,
        revision=profile.revision,
        quantization=profile.quantization,
        weights_sha256=None,
        license_id="no-weights",
        provider_revision_guarantee=True,
    )


def _disabled_model(component: str, *, provider: str = "not-invoked") -> ModelManifest:
    return ModelManifest(
        component=component,
        provider=provider,
        model=f"m8-qwen-demo-{component}",
        revision="1.0.0",
        quantization=None,
        weights_sha256=None,
        license_id="synthetic-demo",
        provider_revision_guarantee=True,
    )


def build_m8_qwen_hearing_demo_config(base: AppConfig) -> AppConfig:
    """Pin three independent Qwen role profiles while keeping M3 screening fake."""

    payload = base.model_dump(mode="json")
    payload.pop("config_sha256")
    for role, profile_name in zip(
        ("prosecutor", "defender", "judge"), QWEN_PROFILE_NAMES, strict=True
    ):
        profile = dict(payload["providers"][f"fake-{role}"])
        profile.update(
            {
                "provider": "openai-compatible",
                "model": QWEN_MODEL_SNAPSHOT,
                "revision": QWEN_MODEL_REVISION,
                "execution_location": "EXTERNAL",
                "transport": "HTTP",
                "endpoint_env": QWEN_ENDPOINT_ENV,
                "api_key_env": QWEN_API_KEY_ENV,
                "timeout_seconds": 60.0,
                "cache_enabled": True,
                "enable_thinking": False,
                "pricing_currency": "CNY",
                "input_cost_per_million_tokens": 2.0,
                "output_cost_per_million_tokens": 8.0,
            }
        )
        payload["providers"][profile_name] = profile
    payload["hearing"].update(
        {
            "prosecutor_profile": QWEN_PROFILE_NAMES[0],
            "defender_profile": QWEN_PROFILE_NAMES[1],
            "judge_profile": QWEN_PROFILE_NAMES[2],
            "max_acquisition_rounds": 1,
            "max_rework_rounds": 1,
        }
    )
    return AppConfig.model_validate(payload)


def _platform_summary() -> PlatformSummary:
    operating_system = {
        "Windows": OperatingSystemFamily.WINDOWS,
        "Linux": OperatingSystemFamily.LINUX,
        "Darwin": OperatingSystemFamily.MACOS,
    }.get(platform.system(), OperatingSystemFamily.OTHER)
    return PlatformSummary(
        os_family=operating_system,
        architecture=platform.machine() or "unknown",
        python_version=platform.python_version(),
        device_class=DeviceClass.CPU_ONLY,
    )


def _manifest(config: AppConfig, source_sha256: str) -> RunManifest:
    decoder = SoftwareComponentManifest(
        component="m8-qwen-demo-synthetic-png",
        package="Pillow",
        version=version("Pillow"),
        license_id="HPND",
    )
    stream = StreamManifest(
        camera_id="cam-01",
        stream_id=DEMO_STREAM_ID,
        input_file_sha256=source_sha256,
        fps_num=30,
        fps_den=1,
        timing_mode="CFR",
        timing_authority="CALLER_ATTESTED",
        timing_evidence_type="CALLER_DECLARATION",
        timing_evidence_sha256=sha256_hex(["m8-qwen-demo-timing", 1, 30, 1]),
        width=DEMO_WIDTH,
        height=DEMO_HEIGHT,
        frame_count=200,
        decoder="synthetic-still-frame",
        decoder_version="1.0.0",
        backend="SEALED_LOCAL_DEMO",
        software_component=decoder.component,
        library=decoder.package,
        library_version=decoder.version,
        codec="FAKE",
        color_conversion="PIL_RGB8",
        pixel_format="RGB8",
        pixel_hash_algorithm="LCPIX1",
    )
    roles = {
        "prosecutor": config.providers[QWEN_PROFILE_NAMES[0]],
        "defender": config.providers[QWEN_PROFILE_NAMES[1]],
        "judge": config.providers[QWEN_PROFILE_NAMES[2]],
    }
    return RunManifest(
        code_commit="local-m8-qwen-demo",
        schema_version=config.schema_version,
        config_sha256=config.config_sha256,
        rule_version=config.rule_version,
        rule_bundle_sha256=sha256_hex(["labcourt-m8-qwen-demo-rules", 1]),
        prompt_bundle_sha256=FROZEN_M3_PROMPT_BUNDLE_SHA256,
        models={
            "detector": _disabled_model("detector", provider="precomputed"),
            "tracker": _disabled_model("tracker", provider="precomputed"),
            "pose": _disabled_model("pose", provider="precomputed"),
            "screening": _model("screening", config.providers[config.screening.provider_profile]),
            "prosecutor": _model("prosecutor", roles["prosecutor"]),
            "defender": _model("defender", roles["defender"]),
            "judge": _model("judge", roles["judge"]),
            "text_embedding": _disabled_model("text_embedding", provider="fake"),
            "visual_embedding": _disabled_model("visual_embedding", provider="fake"),
        },
        privacy_transform_version=config.evidence.privacy_transform_version,
        reproducibility_mode=config.run.reproducibility_mode,
        random_seed=config.run.random_seed,
        decoding_parameters=DecodingParameters(
            temperature=0.0,
            seed=config.run.random_seed,
            max_output_tokens=config.hearing.max_total_output_tokens,
        ),
        platform_summary=_platform_summary(),
        storage_boundary=config.run.storage_boundary,
        streams=(stream,),
        software_components={
            decoder.component: decoder,
            M8_QWEN_DEMO_ACQUISITION_COMPONENT_KEY: M8_QWEN_DEMO_ACQUISITION_COMPONENT,
        },
        pixel_format="RGB8",
        pixel_hash_algorithm="LCPIX1",
        image_encoding_version=config.evidence.encoding_version,
    )


def _canonical_png(path: Path) -> tuple[bytes, bytes]:
    with Image.open(path) as source:
        rgb = source.convert("RGB").resize((DEMO_WIDTH, DEMO_HEIGHT), Image.Resampling.LANCZOS)
        pixels = rgb.tobytes()
    return encode_rgb_png(DEMO_WIDTH, DEMO_HEIGHT, pixels), pixels


def _provider_selections(
    config: AppConfig,
    manifest: RunManifest,
) -> tuple[M8HearingProviderSelectionV1, ...]:
    bindings = (
        (VlmRole.PROSECUTOR, "prosecutor", QWEN_PROFILE_NAMES[0]),
        (VlmRole.DEFENDER, "defender", QWEN_PROFILE_NAMES[1]),
        (VlmRole.JUDGE, "judge", QWEN_PROFILE_NAMES[2]),
    )
    return tuple(
        M8HearingProviderSelectionV1(
            role=role,
            provider_profile=profile_name,
            provider=config.providers[profile_name].provider,
            model=config.providers[profile_name].model,
            revision=config.providers[profile_name].revision,
            model_manifest_id=manifest.models[component].model_manifest_id,
            execution_location=config.providers[profile_name].execution_location,
            transport=config.providers[profile_name].transport,
        )
        for role, component, profile_name in bindings
    )


def prepare_m8_qwen_hearing_demo(
    *,
    output_root: Path,
    primary_image: Path,
    supplementary_image: Path,
    base_config_path: Path,
    clock: Callable[[], datetime] = _now,
) -> M8QwenHearingDemoPreparationV1:
    """Prepare a new synthetic ESCALATED Case using the normal offline M3 route."""

    receipt_path = output_root / "preparation-receipt.json"
    if receipt_path.exists():
        return M8QwenHearingDemoPreparationV1.model_validate_json(
            receipt_path.read_text(encoding="utf-8")
        )
    if not primary_image.is_file() or not supplementary_image.is_file():
        raise FileNotFoundError("both synthetic demo images must exist")
    base = load_config(base_config_path)
    config = build_m8_qwen_hearing_demo_config(base)
    primary_source = primary_image.read_bytes()
    supplementary_source = supplementary_image.read_bytes()
    primary_png, primary_pixels = _canonical_png(primary_image)
    supplementary_png, _supplementary_pixels = _canonical_png(supplementary_image)
    run_id = f"m8-qwen-demo-{uuid4().hex[:16]}"
    manifest = _manifest(config, _sha(primary_source))
    workspace_root = output_root / "hearing-workspace"
    database = workspace_root / config.storage.database_filename
    workspace_root.mkdir(parents=True, exist_ok=True)
    MigrationRunner(database, config.storage.busy_timeout_ms, clock=clock).apply_all()
    frame = FrameRef(
        camera_id="cam-01",
        stream_id=DEMO_STREAM_ID,
        frame_index=90,
        fps_num=30,
        fps_den=1,
        width=DEMO_WIDTH,
        height=DEMO_HEIGHT,
        content_sha256=rgb8_pixel_sha256(DEMO_WIDTH, DEMO_HEIGHT, primary_pixels),
    )
    track_ref = "cam-01:epoch-01:person-01"
    objective = ObjectiveFact(
        fact_id="fact-duration-synthetic-gray-zone",
        kind=ObjectiveFactKind.DURATION_FRAMES,
        value=91,
        source_ref=ArtifactRef(kind=ArtifactKind.FRAME, artifact_id=frame.frame_id),
        source_manifest_id=manifest.models["detector"].model_manifest_id,
        unit="frames",
    )
    event = CandidateEvent(
        camera_id="cam-01",
        stream_id=DEMO_STREAM_ID,
        rule_version=config.rule_version,
        violation_type=ViolationType.PPE_GOGGLES_MISSING,
        evidence_class=EvidenceClass.ABSENCE,
        zone_id=DEMO_ZONE_ID,
        start_frame=0,
        end_frame_exclusive=91,
        trigger_frame=90,
        primary_track_ref=track_ref,
        hard_rule=False,
        l1_score=0.5,
        confirmation=ConfirmationRecord(
            policy=ConfirmationPolicy.STRICT_CAUSAL,
            examined_frame_ids=(frame.frame_id,),
            counterevidence_frame_ids=(),
            post_threshold_recovery_frame_id=None,
            suppressed=False,
            suppression_reason=None,
            resolved_frame=None,
            causal_risk=False,
        ),
        objective_facts=(objective,),
        manifest_id=manifest.manifest_id,
    )
    detection = Detection(
        detection_id="synthetic-person-090",
        frame_id=frame.frame_id,
        label="person",
        bbox=BBoxXYXY(x1=1, y1=1, x2=DEMO_WIDTH - 1, y2=DEMO_HEIGHT - 1),
        score=0.5,
        track_ref=track_ref,
        attributes={"observation_source": "synthetic_weak_label"},
        model_manifest_id=manifest.models["detector"].model_manifest_id,
    )
    source_refs = tuple(
        sorted(
            (
                ArtifactRef(kind=ArtifactKind.FRAME, artifact_id=frame.frame_id),
                ArtifactRef(kind=ArtifactKind.DETECTION, artifact_id=detection.detection_id),
            ),
            key=lambda item: item.sort_key,
        )
    )
    primary_media_sha = _sha(primary_png)
    primary_path = f"{run_id}/frames/{primary_media_sha}.png"
    crop = Crop(
        frame_id=frame.frame_id,
        source=CropSource.ANCHOR_FOCUS,
        bbox=BBoxXYXY(x1=0, y1=0, x2=DEMO_WIDTH, y2=DEMO_HEIGHT),
        source_refs=source_refs,
        local_path=primary_path,
        availability=MediaAvailability.AVAILABLE,
        source_media_sha256=frame.content_sha256,
        pixel_sha256=rgb8_pixel_sha256(DEMO_WIDTH, DEMO_HEIGHT, primary_pixels),
        media_sha256=primary_media_sha,
        output_width=DEMO_WIDTH,
        output_height=DEMO_HEIGHT,
        size_bytes=len(primary_png),
        media_type=MediaType.IMAGE_PNG,
        encoding_version=config.evidence.encoding_version,
        privacy_receipt=PrivacyReceipt(
            policy=PrivacyPolicy.PPE_PRESERVING_REDACTION,
            transform_version=config.evidence.privacy_transform_version,
            media_access=MediaAccess.CLOUD_ALLOWED,
            reason_code=PrivacyReasonCode.PPE_REGION_PRESERVED,
            input_refs=source_refs,
            ppe_type=PpeType.GOGGLES,
            anchor_type=AnchorType.HEAD,
            preserved_regions=(BBoxXYXY(x1=300, y1=120, x2=724, y2=360),),
            keypoints=(
                Keypoint(name="left_eye", x=430.0, y=230.0, score=0.5),
                Keypoint(name="right_eye", x=594.0, y=230.0, score=0.5),
            ),
            anchor_bbox=BBoxXYXY(x1=260, y1=60, x2=764, y2=500),
            association_method=AssociationMethod.KEYPOINT,
            fill_rgb=(0, 0, 0),
        ),
        observability=ObservabilityScore(
            total=0.5,
            components=ObservabilityComponents(
                person_confidence=0.5,
                keypoint_visibility=0.5,
                frontality=0.5,
                sharpness=0.5,
                exposure=0.5,
                non_occlusion=0.5,
            ),
            source=ObservationSource.PRECOMPUTED_FIXTURE,
        ),
        primary_track_ref=track_ref,
        tags={"zone_id": DEMO_ZONE_ID},
    )
    draft = EvidencePackDraft(
        run_id=run_id,
        case_id=derive_case_id(event.event_id),
        version=1,
        complete=True,
        event=event,
        key_frame_ids=(frame.frame_id,),
        temporal_crops=(crop,),
        objective_facts=(objective,),
        track_summary=TrackSummary(
            primary_track_ref=track_ref,
            start_frame=0,
            end_frame_exclusive=91,
            observed_frame_count=91,
        ),
        confirmation_record=event.confirmation,
        observation_sufficiency_input=ObservationSufficiencyInput(
            clear_crop_ids=(),
            unclear_crop_ids=(crop.crop_id,),
            clear_threshold=0.65,
            required_clear_count=2,
            selected_by_observability=True,
        ),
        manifest_id=manifest.manifest_id,
    )
    supplementary_relative_path = f"demo_catalog/{_sha(supplementary_png)}.png"
    with SecureWorkspace(workspace_root, config.storage.max_media_bytes) as workspace:
        for directory in (run_id, f"{run_id}/frames", "demo_catalog"):
            workspace.ensure_private_directory(directory)
        workspace.create_new(primary_path, primary_png, primary_media_sha)
        workspace.create_new(
            supplementary_relative_path,
            supplementary_png,
            _sha(supplementary_png),
        )
        repository = SQLiteEvidenceRepository(
            database,
            config.storage.busy_timeout_ms,
            verifier=StoredPngVerifier(
                run_id=run_id,
                workspace=workspace,
                max_media_bytes=config.storage.max_media_bytes,
                max_image_pixels=config.storage.max_image_pixels,
            ),
            clock=clock,
        )
        repository.register_run(run_id, manifest)
        repository.register_frame(run_id, frame)
        repository.register_detection(run_id, detection)
        repository.create_or_get_case(run_id, event)
        published = repository.publish_pack(run_id, 1, draft)
        repository.verify_current_pack(run_id, published.pack.pack_id)
    prepared = prepare_screening_request(
        published.pack,
        config,
        manifest,
        build_screening_prompt_catalog(manifest),
    )
    screening_payload = ScreeningModelPayload(
        violation_type=ViolationType.PPE_GOGGLES_MISSING,
        evidence_class=EvidenceClass.ABSENCE,
        violation_probability=0.5,
        frame_observations=(
            FrameObservation(
                crop_id=crop.crop_id,
                wear_status=WearStatus.UNCLEAR,
                reason_summary="Synthetic glare and occlusion make eyewear indeterminate.",
            ),
        ),
        evidence_citations=(
            EvidenceCitation(
                evidence_ref=ArtifactRef(kind=ArtifactKind.CROP, artifact_id=crop.crop_id)
            ),
        ),
        objective_claims=(
            ObjectiveClaim(
                kind=ObjectiveFactKind.DURATION_FRAMES,
                value=91,
                evidence_ref=ArtifactRef(
                    kind=ArtifactKind.OBJECTIVE_FACT,
                    artifact_id=objective.fact_id,
                ),
            ),
        ),
        prosecution_summary="Synthetic PPE evidence is deliberately ambiguous.",
        rationale_summary="A 0.50 fixture probability exercises the gray-zone route only.",
    )
    fixture = FakeVLMFixtureBundle(
        schema_version="m3-fake-vlm-fixture-bundle-v1",
        fixtures=(
            FakeVLMResponseFixtureInput(
                disposition=FakeVLMFixtureDisposition.RESPONSE,
                cache_key=prepared.request.cache_key,
                raw_response_utf8=canonical_json(screening_payload.model_dump(mode="json")),
                input_tokens=16,
                output_tokens=16,
                latency_ms=1,
            ),
        ),
    )
    with open_m3_operations_service(
        config=config,
        run_id=run_id,
        workspace_root=workspace_root,
        database_path=database,
        fixture_bundle=fixture,
        clock=clock,
    ) as screening:
        report = screening.process_run(case_id=published.pack.case_id, max_cases=1)
    if len(report.outcomes) != 1 or report.outcomes[0].status != CaseStatus.ESCALATED:
        raise RuntimeError("synthetic gray-zone fixture did not produce ESCALATED")
    repository = SQLiteEvidenceRepository(database, config.storage.busy_timeout_ms, clock=clock)
    case = repository.load_case(run_id, published.pack.case_id)
    if case.case.status != CaseStatus.ESCALATED:
        raise RuntimeError("prepared Case is not ESCALATED")
    screening_result = case.case.screening_results[-1]
    if screening_result.decision != ScreeningDecision.ESCALATE:
        raise RuntimeError("prepared screening did not choose ESCALATE")
    start = M8HearingStartRequestV1(
        run_id=run_id,
        case_id=case.case.case_id,
        source_status=CaseStatus.ESCALATED,
        source_screening_id=screening_result.screening_id,
        source_evidence_pack_id=published.pack.pack_id,
        source_evidence_pack_version=published.pack.version,
        model_mode=M8HearingModelMode.OPENAI_COMPATIBLE_QWEN,
        request_manifest_id=manifest.manifest_id,
    )
    evidence = (
        M8QwenHearingDemoEvidenceV1(
            role=M8QwenHearingDemoEvidenceRole.PRIMARY,
            artifact_ref=ArtifactRef(kind=ArtifactKind.CROP, artifact_id=crop.crop_id),
            source_file_sha256=_sha(primary_source),
            canonical_media_sha256=primary_media_sha,
            prompt_sha256=_sha(PRIMARY_IMAGE_PROMPT.encode("utf-8")),
            width=DEMO_WIDTH,
            height=DEMO_HEIGHT,
            size_bytes=len(primary_png),
            preauthorized_acquisition_catalog=False,
        ),
        M8QwenHearingDemoEvidenceV1(
            role=M8QwenHearingDemoEvidenceRole.SUPPLEMENTARY,
            artifact_ref=ArtifactRef(kind=ArtifactKind.MEDIA, artifact_id=_sha(supplementary_png)),
            source_file_sha256=_sha(supplementary_source),
            canonical_media_sha256=_sha(supplementary_png),
            prompt_sha256=_sha(SUPPLEMENTARY_IMAGE_PROMPT.encode("utf-8")),
            width=DEMO_WIDTH,
            height=DEMO_HEIGHT,
            size_bytes=len(supplementary_png),
            preauthorized_acquisition_catalog=True,
        ),
    )
    receipt = M8QwenHearingDemoPreparationV1(
        run_id=run_id,
        case_id=case.case.case_id,
        config_sha256=config.config_sha256,
        manifest_id=manifest.manifest_id,
        provider_selections=_provider_selections(config, manifest),
        evidence=evidence,
        start_request=start,
    )
    _write_equal_or_new(output_root / "qwen-config.json", _artifact_bytes(config))
    _write_equal_or_new(output_root / "run-manifest.json", _artifact_bytes(manifest))
    _write_equal_or_new(output_root / "start-request.json", _artifact_bytes(start))
    _write_equal_or_new(
        output_root / "supplementary-path.txt",
        (supplementary_relative_path + "\n").encode("utf-8"),
    )
    _write_equal_or_new(receipt_path, _artifact_bytes(receipt))
    return receipt


@dataclass(slots=True)
class _CapturedProviderEnvelope:
    provider_profile: str
    provider_response_id: str


class _CapturingTransport:
    def __init__(
        self,
        profile: str,
        delegate: OpenAICompatibleTransport,
        captured: list[_CapturedProviderEnvelope],
    ) -> None:
        self._profile = profile
        self._delegate = delegate
        self._captured = captured

    def send(self, request: OpenAICompatibleTransportRequest) -> OpenAICompatibleTransportResponse:
        response = self._delegate.send(request)
        try:
            envelope = json.loads(response.body)
            response_id = envelope.get("id") if isinstance(envelope, dict) else None
        except (UnicodeDecodeError, json.JSONDecodeError):
            response_id = None
        if (
            isinstance(response_id, str)
            and 1 <= len(response_id) <= 512
            and response_id.strip() == response_id
            and all(ord(character) >= 32 for character in response_id)
        ):
            self._captured.append(_CapturedProviderEnvelope(self._profile, response_id))
        return response


def _http_json(
    base_url: str,
    method: str,
    path: str,
    payload: object | None = None,
    *,
    timeout_seconds: float = 30.0,
) -> tuple[int, dict[str, Any]]:
    body = None if payload is None else canonical_bytes(payload)
    request = urllib.request.Request(
        base_url + path,
        method=method,
        data=body,
        headers={
            "Authorization": f"Bearer {M8_PERSONAL_DEMO_ROLE_TOKENS['safety']}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


def _provider_receipts(
    preparation: M8QwenHearingDemoPreparationV1,
    view: M8HearingViewV1,
    captured: list[_CapturedProviderEnvelope],
) -> tuple[M8QwenHearingProviderReceiptV1, ...]:
    profile_by_role = {item.role: item.provider_profile for item in preparation.provider_selections}
    envelope_ids: dict[str, list[str]] = {profile: [] for profile in QWEN_PROFILE_NAMES}
    for item in captured:
        envelope_ids[item.provider_profile].append(item.provider_response_id)
    counters = {profile: 0 for profile in QWEN_PROFILE_NAMES}
    values: list[M8QwenHearingProviderReceiptV1] = []
    for response in view.model_responses:
        profile = profile_by_role[response.role]
        index = counters[profile]
        if index >= len(envelope_ids[profile]):
            continue
        counters[profile] += 1
        values.append(
            M8QwenHearingProviderReceiptV1(
                role=response.role,
                provider_profile=profile,
                provider_response_id=envelope_ids[profile][index],
                labcourt_response_id=response.response_id,
                raw_response_ref=response.raw_response_ref,
                content_sha256=response.content_sha256,
                input_tokens=response.input_tokens,
                output_tokens=response.output_tokens,
                latency_ms=response.latency_ms,
                estimated_cost_cny=(response.input_tokens * 2.0 + response.output_tokens * 8.0)
                / 1_000_000,
            )
        )
    return tuple(values)


def _attempt_from_view(
    preparation: M8QwenHearingDemoPreparationV1,
    view: M8HearingViewV1,
    provider_receipts: tuple[M8QwenHearingProviderReceiptV1, ...],
    *,
    attempted_at: datetime,
    api_http_status: int,
) -> M8QwenHearingDemoAttemptReceiptV1:
    response_ids = tuple(item.response_id for item in view.model_responses)
    failure_ids = tuple(item.authority_id for item in view.typed_failures)
    receipts_complete = tuple(
        item.labcourt_response_id for item in provider_receipts
    ) == response_ids and {item.role for item in provider_receipts} == {
        VlmRole.PROSECUTOR,
        VlmRole.DEFENDER,
        VlmRole.JUDGE,
    }
    if (
        view.eligibility in {M8HearingEligibility.COMPLETED, M8HearingEligibility.HUMAN_REVIEW}
        and view.final_verdict is not None
        and view.l5_status != M8HearingL5Status.NOT_RUN
        and len(response_ids) >= 3
        and receipts_complete
    ):
        outcome = M8QwenHearingDemoAttemptOutcome.COMPLETED
        delivery = M8QwenHearingDemoDeliveryState.COMPLETED
        reason = None
        external_call_attempted = True
    elif failure_ids:
        outcome = M8QwenHearingDemoAttemptOutcome.AUDITABLE_FAILURE
        delivery = M8QwenHearingDemoDeliveryState(view.typed_failures[-1].delivery_certainty.value)
        reason = view.typed_failures[-1].failure_code.value
        external_call_attempted = delivery == M8QwenHearingDemoDeliveryState.COMPLETED
    elif (
        view.eligibility in {M8HearingEligibility.COMPLETED, M8HearingEligibility.HUMAN_REVIEW}
        and view.final_verdict is not None
        and view.l5_status != M8HearingL5Status.NOT_RUN
        and len(response_ids) >= 3
    ):
        outcome = M8QwenHearingDemoAttemptOutcome.AUDITABLE_FAILURE
        delivery = M8QwenHearingDemoDeliveryState.COMPLETED
        reason = "PROVIDER_RECEIPT_INCOMPLETE"
        external_call_attempted = True
    else:
        outcome = M8QwenHearingDemoAttemptOutcome.RECOVERY_REQUIRED
        delivery = M8QwenHearingDemoDeliveryState.UNKNOWN
        reason = "DELIVERY_UNKNOWN_RECOVERY_REQUIRED"
        external_call_attempted = True
    return M8QwenHearingDemoAttemptReceiptV1(
        preparation_id=preparation.preparation_id,
        attempted_at=attempted_at,
        outcome=outcome,
        delivery_state=delivery,
        api_http_status=api_http_status,
        reason_code=reason,
        view_id=view.view_id,
        hearing_session_id=view.hearing_session_id,
        role_response_ids=response_ids,
        provider_receipts=provider_receipts,
        typed_failure_ids=failure_ids,
        l5_status=view.l5_status,
        external_call_attempted=external_call_attempted,
    )


def _markdown_report(
    preparation: M8QwenHearingDemoPreparationV1,
    attempt: M8QwenHearingDemoAttemptReceiptV1,
    view: M8HearingViewV1 | None,
) -> str:
    lines = [
        "# LabCourt M8 真实 Qwen 会审记录",
        "",
        "> 合成演示案例；不含真实人物，不是真值或准确率评估。",
        "",
        f"- Run：`{preparation.run_id}`",
        f"- Case：`{preparation.case_id}`",
        f"- 模型：`{QWEN_MODEL_SNAPSHOT}`（thinking=false，JSON mode）",
        f"- 结果：`{attempt.outcome.value}`；交付状态：`{attempt.delivery_state.value}`",
        f"- L5：`{attempt.l5_status.value}`",
        "",
        "## Provider 与 LabCourt 响应凭据",
        "",
        "| 角色 | Profile | Provider ID | LabCourt response ID | Raw reference | Tokens(in/out) | 时延(ms) |",
        "|---|---|---|---|---|---:|---:|",
    ]
    for item in attempt.provider_receipts:
        lines.append(
            f"| {item.role.value} | {item.provider_profile} | {item.provider_response_id} | "
            f"{item.labcourt_response_id} | {item.raw_response_ref} | "
            f"{item.input_tokens}/{item.output_tokens} | "
            f"{item.latency_ms} (~CNY {item.estimated_cost_cny:.8f}) |"
        )
    if not attempt.provider_receipts:
        lines.append("| — | — | — | — | — | — | — |")
    if view is not None:
        lines.extend(["", "## 控方、辩方与裁决方结构化输出", ""])
        for output in view.role_outputs:
            lines.extend(
                [
                    f"### {output.role.value} · 第 {output.round_index} 轮",
                    "",
                    "```json",
                    json.dumps(
                        output.payload.model_dump(mode="json"), ensure_ascii=False, indent=2
                    ),
                    "```",
                    "",
                ]
            )
        lines.extend(["## 补证记录", ""])
        lines.append(
            json.dumps(
                {
                    "requests": [
                        item.model_dump(mode="json") for item in view.acquisition_requests
                    ],
                    "receipts": [
                        item.model_dump(mode="json") for item in view.tool_execution_receipts
                    ],
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        lines.extend(["", "## 最终裁决与 L5", "", "```json"])
        lines.append(
            json.dumps(
                {
                    "final_verdict": (
                        view.final_verdict.model_dump(mode="json")
                        if view.final_verdict is not None
                        else None
                    ),
                    "procedural_reviews": [
                        item.model_dump(mode="json") for item in view.procedural_reviews
                    ],
                    "l5_status": view.l5_status.value,
                    "cited_evidence_refs": [
                        item.model_dump(mode="json") for item in view.cited_evidence_refs
                    ],
                    "cited_precedent_refs": [
                        item.model_dump(mode="json") for item in view.cited_precedent_refs
                    ],
                    "typed_failures": [
                        item.model_dump(mode="json") for item in view.typed_failures
                    ],
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        lines.extend(["```", ""])
    if attempt.reason_code is not None:
        lines.extend(["## Typed failure", "", f"`{attempt.reason_code}`", ""])
    lines.extend(
        [
            "## 已知边界",
            "",
            "- 预封存补证仅为本地合成 demo 的 RECROP 适配器，不代表生产取证。",
            "- 弱标签与模型意见都不是真值；最终结果仍受既有证据约束与 L5 程序门控。",
            "- 报告不嵌入原始 provider 响应或任何凭据。",
            "",
        ]
    )
    return "\n".join(lines)


def load_m8_qwen_hearing_demo(
    output_root: Path,
) -> tuple[AppConfig, M8QwenHearingDemoPreparationV1]:
    config = AppConfig.model_validate_json((output_root / "qwen-config.json").read_text("utf-8"))
    preparation = M8QwenHearingDemoPreparationV1.model_validate_json(
        (output_root / "preparation-receipt.json").read_text("utf-8")
    )
    if config.config_sha256 != preparation.config_sha256:
        raise ValueError("prepared Qwen config hash mismatch")
    return config, preparation


@contextmanager
def _demo_api(
    *,
    output_root: Path,
    config: AppConfig,
    preparation: M8QwenHearingDemoPreparationV1,
    transports: Mapping[str, OpenAICompatibleTransport] | None,
    environment: Mapping[str, str] | None,
    port: int,
    start_enabled: bool,
) -> Iterator[tuple[str, list[_CapturedProviderEnvelope]]]:
    captured: list[_CapturedProviderEnvelope] = []
    wrapped = (
        {
            profile: _CapturingTransport(profile, transport, captured)
            for profile, transport in transports.items()
        }
        if transports is not None
        else None
    )
    workspace_root = output_root / "hearing-workspace"
    supplementary_path = (output_root / "supplementary-path.txt").read_text("utf-8").strip()
    with open_m8_hearing_runtime(
        config=config,
        run_id=preparation.run_id,
        workspace_root=workspace_root,
        database_path=workspace_root / config.storage.database_filename,
        location_by_zone={zone.zone_id: DEMO_LOCATION_ID for zone in config.zones},
        model_mode=M8HearingModelMode.OPENAI_COMPATIBLE_QWEN,
        environment=environment,
        transports=wrapped,
        acquisition_executor_factory=lambda workspace, manifest: M8QwenDemoSealedRecropExecutor(
            workspace=workspace,
            manifest=manifest,
            supplementary_relative_path=supplementary_path,
            max_image_pixels=config.storage.max_image_pixels,
        ),
    ) as runtime:
        assembly = assemble_m8_personal_demo_api(
            output_root / "operations" / "labcourt.sqlite3",
            port,
        )
        assembly.server.hearing_service = M8HearingApiService(
            assembly.operations_repository,
            {preparation.run_id: runtime},
            start_enabled=start_enabled,
        )
        thread = threading.Thread(target=assembly.server.serve_forever, daemon=True)
        thread.start()
        try:
            yield f"http://127.0.0.1:{assembly.server.server_port}", captured
        finally:
            assembly.server.shutdown()
            assembly.server.server_close()
            thread.join(timeout=5)


def run_m8_qwen_hearing_demo(
    *,
    output_root: Path,
    environment: Mapping[str, str] | None = None,
    transports: Mapping[str, OpenAICompatibleTransport] | None = None,
    port: int = 0,
    clock: Callable[[], datetime] = _now,
) -> M8QwenHearingDemoAttemptReceiptV1:
    """Make no more than one POST; never retry or select an offline fallback."""

    attempt_path = output_root / "attempt-receipt.json"
    if attempt_path.exists():
        return M8QwenHearingDemoAttemptReceiptV1.model_validate_json(
            attempt_path.read_text("utf-8")
        )
    config, preparation = load_m8_qwen_hearing_demo(output_root)
    effective_environment = dict(environment or {})
    if transports is None and (
        not effective_environment.get(QWEN_ENDPOINT_ENV)
        or not effective_environment.get(QWEN_API_KEY_ENV)
    ):
        attempt = M8QwenHearingDemoAttemptReceiptV1(
            preparation_id=preparation.preparation_id,
            attempted_at=clock(),
            outcome=M8QwenHearingDemoAttemptOutcome.CONFIGURATION_FAILED,
            delivery_state=M8QwenHearingDemoDeliveryState.DEFINITELY_NOT_SENT,
            reason_code="QWEN_CONFIGURATION_MISSING",
            l5_status=M8HearingL5Status.NOT_RUN,
            external_call_attempted=False,
        )
        _write_equal_or_new(attempt_path, _artifact_bytes(attempt))
        _write_equal_or_new(
            output_root / "hearing-record.md",
            _markdown_report(preparation, attempt, None).encode("utf-8"),
        )
        return attempt
    active_transports = transports
    if active_transports is None:
        try:
            active_transports = {
                profile_name: build_openai_compatible_transport(
                    config.providers[profile_name],
                    environment=effective_environment,
                )
                for profile_name in QWEN_PROFILE_NAMES
            }
        except OpenAICompatibleTransportConfigurationError as error:
            attempt = M8QwenHearingDemoAttemptReceiptV1(
                preparation_id=preparation.preparation_id,
                attempted_at=clock(),
                outcome=M8QwenHearingDemoAttemptOutcome.CONFIGURATION_FAILED,
                delivery_state=M8QwenHearingDemoDeliveryState.DEFINITELY_NOT_SENT,
                reason_code=f"QWEN_{error.code.value}",
                l5_status=M8HearingL5Status.NOT_RUN,
                external_call_attempted=False,
            )
            _write_equal_or_new(attempt_path, _artifact_bytes(attempt))
            _write_equal_or_new(
                output_root / "hearing-record.md",
                _markdown_report(preparation, attempt, None).encode("utf-8"),
            )
            return attempt
    attempted_at = clock()
    provider_timeout = max(
        float(config.providers[profile].timeout_seconds) for profile in QWEN_PROFILE_NAMES
    )
    post_timeout = (
        3
        * (1 + config.hearing.max_acquisition_rounds + config.hearing.max_rework_rounds)
        * 2
        * provider_timeout
        + 30.0
    )
    with _demo_api(
        output_root=output_root,
        config=config,
        preparation=preparation,
        transports=active_transports,
        environment=effective_environment,
        port=port,
        start_enabled=True,
    ) as (base_url, captured):
        path = f"/api/m8/runs/{preparation.run_id}/cases/{preparation.case_id}/hearing"
        initial_status, initial_body = _http_json(base_url, "GET", path)
        initial = M8HearingViewV1.model_validate(initial_body)
        if initial.hearing_session_id is None:
            post_status, _post_body = _http_json(
                base_url,
                "POST",
                path,
                preparation.start_request.model_dump(mode="json"),
                timeout_seconds=post_timeout,
            )
        else:
            post_status = initial_status
        get_status, view_body = _http_json(base_url, "GET", path)
        view = M8HearingViewV1.model_validate(view_body)
        provider_receipts = _provider_receipts(preparation, view, captured)
        attempt = _attempt_from_view(
            preparation,
            view,
            provider_receipts,
            attempted_at=attempted_at,
            api_http_status=post_status if post_status else get_status,
        )
    _write_equal_or_new(output_root / "hearing-view.json", _artifact_bytes(view))
    _write_equal_or_new(
        output_root / "provider-receipts.json",
        _artifact_bytes([item.model_dump(mode="json") for item in provider_receipts]),
    )
    _write_equal_or_new(attempt_path, _artifact_bytes(attempt))
    _write_equal_or_new(
        output_root / "hearing-record.md",
        _markdown_report(preparation, attempt, view).encode("utf-8"),
    )
    return attempt


def serve_m8_qwen_hearing_demo_results(*, output_root: Path, port: int) -> None:
    """Serve persisted GET projection; POST is rejected before M4 runtime invocation."""

    config, preparation = load_m8_qwen_hearing_demo(output_root)

    class _DisabledTransport:
        def send(
            self, _request: OpenAICompatibleTransportRequest
        ) -> OpenAICompatibleTransportResponse:
            raise AssertionError("read-only result server cannot call a provider")

    transports = {profile: _DisabledTransport() for profile in QWEN_PROFILE_NAMES}
    with _demo_api(
        output_root=output_root,
        config=config,
        preparation=preparation,
        transports=transports,
        environment={},
        port=port,
        start_enabled=False,
    ) as (base_url, _captured):
        access = {
            "base_url": base_url,
            "hearing_path": (
                f"/api/m8/runs/{preparation.run_id}/cases/{preparation.case_id}/hearing"
            ),
            "bearer_token": M8_PERSONAL_DEMO_ROLE_TOKENS["safety"],
            "post_enabled": False,
        }
        _write_equal_or_new(output_root / "results-api-access.json", _artifact_bytes(access))
        threading.Event().wait()


__all__ = [
    "PRIMARY_IMAGE_PROMPT",
    "QWEN_API_KEY_ENV",
    "QWEN_ENDPOINT_ENV",
    "QWEN_MODEL_SNAPSHOT",
    "QWEN_PROFILE_NAMES",
    "SUPPLEMENTARY_IMAGE_PROMPT",
    "build_m8_qwen_hearing_demo_config",
    "load_m8_qwen_hearing_demo",
    "prepare_m8_qwen_hearing_demo",
    "run_m8_qwen_hearing_demo",
    "serve_m8_qwen_hearing_demo_results",
]
