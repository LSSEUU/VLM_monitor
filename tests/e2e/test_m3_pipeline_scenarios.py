"""Offline M3 scenario matrix over real SQLite and secure response storage.

All media and model outputs in this module are synthetic fixtures.  These tests
exercise deterministic workflow behavior; they do not measure or claim model
accuracy, latency, throughput, cost, or real-world safety performance.
"""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import pytest

from labcourt.adapters.storage import SecureWorkspace
from labcourt.adapters.storage.model_response_store import SecureModelResponseStore
from labcourt.adapters.storage.sqlite_m3_repository import SQLiteM3Repository
from labcourt.adapters.storage.sqlite_repository import (
    MigrationRunner,
    SQLiteEvidenceRepository,
)
from labcourt.adapters.vlm import (
    OUTAGE_FIXTURE,
    AppendOnlyRenderedPromptRegistry,
    DeterministicFakeVLMClient,
    FakeVLMFixture,
)
from labcourt.application.model_parser import inspect_screening_response
from labcourt.application.procedural_review import DeterministicProceduralReviewVerifier
from labcourt.application.screening_coordinator import ScreeningCoordinator
from labcourt.application.screening_request import (
    PreparedScreeningRequest,
    prepare_screening_request,
)
from labcourt.application.structure_repair import prepare_structure_repair_request
from labcourt.config_loader import load_config
from labcourt.contracts.canonical import canonical_bytes, sha256_hex
from labcourt.contracts.config import AppConfig
from labcourt.contracts.detections import Detection, Keypoint
from labcourt.contracts.enums import (
    AnchorType,
    ArtifactKind,
    AssociationMethod,
    BacklogReasonCode,
    CaseStatus,
    CropSource,
    EvidenceClass,
    MediaAccess,
    MediaAvailability,
    MediaType,
    ModelParseStatus,
    ObjectiveFactKind,
    ObservationSource,
    PpeType,
    PrivacyPolicy,
    PrivacyReasonCode,
    ProceduralDefectCode,
    ScreeningDecision,
    VerdictDecision,
    VerificationStatus,
    VlmCallPurpose,
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
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.screening import (
    VLMCallRequest,
    VLMResponse,
    derive_model_response_id,
)
from labcourt.contracts.storage import ArtifactRef, ArtifactVerification
from labcourt.exceptions import ContractViolation
from labcourt.ports.prompts import PromptCatalog
from labcourt.ports.vlm import RawModelResponseVerifier
from labcourt.services.m3 import build_screening_prompt_catalog

ROOT = Path(__file__).parents[2]
M2_FIXTURES = ROOT / "tests" / "fixtures" / "m2"
RUN_ID = "run-01"
BUSY_TIMEOUT_MS = 5_000
RECORDED_AT = datetime(2026, 7, 28, 10, 15, tzinfo=UTC)
_NO_OBJECTIVE_CLAIM = object()


class _VerifiedSyntheticCropStore:
    """Establish closure authority without reading real-person media."""

    def verify_crop(self, crop: Crop) -> ArtifactVerification:
        return ArtifactVerification(
            artifact_ref=ArtifactRef(kind=ArtifactKind.CROP, artifact_id=crop.crop_id),
            status=VerificationStatus.VERIFIED,
            availability=crop.availability,
            media_type=crop.media_type,
            expected_source_pixel_sha256=crop.source_media_sha256,
            actual_source_pixel_sha256=crop.source_media_sha256,
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

    def reference_exists(self, run_id: str, ref: ArtifactRef) -> bool:
        del run_id, ref
        return False


@dataclass(slots=True)
class _CountingFakeVLM:
    delegate: DeterministicFakeVLMClient
    calls: list[VLMCallRequest] = field(default_factory=list)

    def complete(self, request: VLMCallRequest) -> VLMResponse:
        self.calls.append(request)
        return self.delegate.complete(request)


class _RawVerifierBinding:
    """Bind the E2E repository to the currently open secure response store."""

    def __init__(self) -> None:
        self._delegate: RawModelResponseVerifier | None = None

    def bind(self, delegate: RawModelResponseVerifier) -> None:
        self._delegate = delegate

    def verify_raw_response(
        self,
        run_id: str,
        request: VLMCallRequest,
        response: VLMResponse,
    ) -> VLMResponse:
        if self._delegate is None:
            raise ContractViolation("raw response verifier is not bound to an open workspace")
        return self._delegate.verify_raw_response(run_id, request, response)


class _PublishPackAfterResponseVLM:
    def __init__(
        self,
        delegate: DeterministicFakeVLMClient,
        evidence: SQLiteEvidenceRepository,
        next_draft: EvidencePackDraft,
    ) -> None:
        self._delegate = delegate
        self._evidence = evidence
        self._next_draft = next_draft
        self.calls: list[VLMCallRequest] = []

    def complete(self, request: VLMCallRequest) -> VLMResponse:
        self.calls.append(request)
        response = self._delegate.complete(request)
        current = self._evidence.load_case(request.run_id, request.case_id)
        self._evidence.publish_pack(request.run_id, current.revision, self._next_draft)
        return response


@dataclass(frozen=True, slots=True)
class _Runtime:
    database: Path
    workspace_root: Path
    config: AppConfig
    manifest: RunManifest
    evidence: SQLiteEvidenceRepository
    review_verifier: DeterministicProceduralReviewVerifier
    screening: SQLiteM3Repository
    raw_verifier: _RawVerifierBinding
    pack: EvidencePack
    catalog: PromptCatalog
    prepared: PreparedScreeningRequest


def _clock() -> datetime:
    return RECORDED_AT


def _manifest() -> RunManifest:
    return RunManifest.model_validate_json(
        (M2_FIXTURES / "run-manifest-fake.json").read_text(encoding="utf-8")
    )


def _event(evidence_class: EvidenceClass) -> CandidateEvent:
    filename = (
        "candidate-event-presence.json"
        if evidence_class == EvidenceClass.PRESENCE
        else "candidate-event-absence-strict.json"
    )
    event = CandidateEvent.model_validate_json((M2_FIXTURES / filename).read_text(encoding="utf-8"))
    if evidence_class == EvidenceClass.ABSENCE:
        return event
    # Keep the threshold matrix independent of the separately tested strong-signal
    # conflict rule: this synthetic L1 score is below the configured strong threshold.
    payload = event.model_dump(mode="json")
    payload.pop("event_id", None)
    payload["l1_score"] = 0.4
    return CandidateEvent.model_validate(payload)


def _frame(event: CandidateEvent, frame_index: int) -> FrameRef:
    return FrameRef(
        camera_id=event.camera_id,
        stream_id=event.stream_id,
        frame_index=frame_index,
        fps_num=30,
        fps_den=1,
        width=640,
        height=480,
        content_sha256=sha256_hex(["m3-e2e-synthetic-frame", event.stream_id, frame_index]),
    )


def _presence_draft(
    event: CandidateEvent,
    frame: FrameRef,
    *,
    extra_objective_facts: tuple[ObjectiveFact, ...] = (),
) -> EvidencePackDraft:
    frame_ref = ArtifactRef(kind=ArtifactKind.FRAME, artifact_id=frame.frame_id)
    detection_ref = ArtifactRef(
        kind=ArtifactKind.DETECTION,
        artifact_id="det-bottle-090",
    )
    source_refs = tuple(sorted((frame_ref, detection_ref), key=lambda ref: ref.sort_key))
    media_sha256 = sha256_hex(["m3-e2e-presence-media", event.event_id])
    crop = Crop(
        frame_id=frame.frame_id,
        source=CropSource.DETECTION_FOCUS,
        bbox=BBoxXYXY(x1=10, y1=20, x2=110, y2=220),
        source_refs=source_refs,
        local_path=f"{RUN_ID}/frames/{media_sha256}.png",
        availability=MediaAvailability.AVAILABLE,
        source_media_sha256=frame.content_sha256,
        pixel_sha256=sha256_hex(["m3-e2e-presence-pixels", event.event_id]),
        media_sha256=media_sha256,
        output_width=100,
        output_height=200,
        size_bytes=512,
        media_type=MediaType.IMAGE_PNG,
        encoding_version="png-v1",
        privacy_receipt=PrivacyReceipt(
            policy=PrivacyPolicy.FULL_REDACTION,
            transform_version="ppe-redaction-v1",
            media_access=MediaAccess.LOCAL_ONLY,
            reason_code=PrivacyReasonCode.POLICY_LOCAL_ONLY,
            input_refs=source_refs,
            fill_rgb=(0, 0, 0),
        ),
        primary_track_ref=event.primary_track_ref,
        tags={"zone_id": event.zone_id},
    )
    return EvidencePackDraft(
        run_id=RUN_ID,
        case_id=derive_case_id(event.event_id),
        version=1,
        complete=True,
        event=event,
        key_frame_ids=(frame.frame_id,),
        focus_crops=(crop,),
        objective_facts=tuple(
            sorted((*event.objective_facts, *extra_objective_facts), key=lambda fact: fact.fact_id)
        ),
        track_summary=TrackSummary(
            primary_track_ref=event.primary_track_ref,
            start_frame=event.start_frame,
            end_frame_exclusive=event.end_frame_exclusive,
            observed_frame_count=event.end_frame_exclusive - event.start_frame,
        ),
        confirmation_record=event.confirmation,
        manifest_id=event.manifest_id,
    )


def _absence_crop(event: CandidateEvent, frame: FrameRef, *, clear: bool) -> Crop:
    frame_ref = ArtifactRef(kind=ArtifactKind.FRAME, artifact_id=frame.frame_id)
    score = 0.9 if clear else 0.2
    preserved = BBoxXYXY(x1=10, y1=10, x2=90, y2=55)
    media_sha256 = sha256_hex(["m3-e2e-absence-media", frame.frame_id])
    return Crop(
        frame_id=frame.frame_id,
        source=CropSource.ANCHOR_FOCUS,
        bbox=BBoxXYXY(x1=0, y1=0, x2=100, y2=100),
        source_refs=(frame_ref,),
        local_path=f"{RUN_ID}/frames/{media_sha256}.png",
        availability=MediaAvailability.AVAILABLE,
        source_media_sha256=frame.content_sha256,
        pixel_sha256=sha256_hex(["m3-e2e-absence-pixels", frame.frame_id]),
        media_sha256=media_sha256,
        output_width=100,
        output_height=100,
        size_bytes=384,
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


def _absence_draft(
    event: CandidateEvent,
    frames: dict[int, FrameRef],
) -> EvidencePackDraft:
    temporal_crops = tuple(
        _absence_crop(event, frames[index], clear=clear)
        for index, clear in ((0, True), (75, True), (100, False), (149, True))
    )
    clear_crop_ids = tuple(
        sorted(
            crop.crop_id
            for crop in temporal_crops
            if crop.observability is not None and crop.observability.total >= 0.65
        )
    )
    unclear_crop_ids = tuple(
        sorted(
            crop.crop_id
            for crop in temporal_crops
            if crop.observability is not None and crop.observability.total < 0.65
        )
    )
    return EvidencePackDraft(
        run_id=RUN_ID,
        case_id=derive_case_id(event.event_id),
        version=1,
        complete=True,
        event=event,
        key_frame_ids=tuple(frames[index].frame_id for index in sorted(frames)),
        temporal_crops=temporal_crops,
        objective_facts=event.objective_facts,
        track_summary=TrackSummary(
            primary_track_ref=event.primary_track_ref,
            start_frame=event.start_frame,
            end_frame_exclusive=152,
            observed_frame_count=151,
        ),
        confirmation_record=event.confirmation,
        observation_sufficiency_input=ObservationSufficiencyInput(
            clear_crop_ids=clear_crop_ids,
            unclear_crop_ids=unclear_crop_ids,
            clear_threshold=0.65,
            required_clear_count=2,
            selected_by_observability=True,
        ),
        manifest_id=event.manifest_id,
    )


def _setup_runtime(
    tmp_path: Path,
    evidence_class: EvidenceClass,
    *,
    person_count: int | None = None,
) -> _Runtime:
    config = load_config(ROOT / "configs" / "demo.yaml")
    manifest = _manifest()
    database = tmp_path / "labcourt.sqlite3"
    workspace_root = tmp_path / "workspace"
    workspace_root.mkdir()
    MigrationRunner(database, BUSY_TIMEOUT_MS, clock=_clock).apply_all()
    evidence = SQLiteEvidenceRepository(
        database,
        BUSY_TIMEOUT_MS,
        verifier=_VerifiedSyntheticCropStore(),
        clock=_clock,
    )
    evidence.register_run(RUN_ID, manifest)
    event = _event(evidence_class)
    if evidence_class == EvidenceClass.PRESENCE:
        frame = _frame(event, event.trigger_frame)
        evidence.register_frame(RUN_ID, frame)
        evidence.register_detection(
            RUN_ID,
            Detection(
                detection_id="det-bottle-090",
                frame_id=frame.frame_id,
                label="reagent_bottle",
                bbox=BBoxXYXY(x1=10, y1=20, x2=110, y2=220),
                score=0.92,
                track_ref=event.primary_track_ref,
                model_manifest_id=manifest.models["detector"].model_manifest_id,
            ),
        )
        extra_objective_facts: tuple[ObjectiveFact, ...] = ()
        if person_count is not None:
            extra_objective_facts = (
                ObjectiveFact(
                    fact_id="fact-person-count",
                    kind=ObjectiveFactKind.PERSON_COUNT,
                    value=person_count,
                    source_ref=ArtifactRef(
                        kind=ArtifactKind.FRAME,
                        artifact_id=frame.frame_id,
                    ),
                    source_manifest_id=manifest.models["detector"].model_manifest_id,
                    unit="persons",
                ),
            )
        draft = _presence_draft(
            event,
            frame,
            extra_objective_facts=extra_objective_facts,
        )
    else:
        frames = {index: _frame(event, index) for index in (0, 75, 100, 149, 150, 151)}
        for frame in frames.values():
            evidence.register_frame(RUN_ID, frame)
        draft = _absence_draft(event, frames)
    evidence.create_or_get_case(RUN_ID, event)
    published = evidence.publish_pack(RUN_ID, 1, draft)
    review_verifier = DeterministicProceduralReviewVerifier(config, evidence)
    raw_verifier = _RawVerifierBinding()
    screening = SQLiteM3Repository(
        database,
        BUSY_TIMEOUT_MS,
        clock=_clock,
        current_pack_verifier=evidence.verify_current_pack,
        raw_response_verifier=raw_verifier,
        procedural_review_verifier=review_verifier,
    )
    catalog = build_screening_prompt_catalog(manifest)
    prepared = prepare_screening_request(published.pack, config, manifest, catalog)
    return _Runtime(
        database=database,
        workspace_root=workspace_root,
        config=config,
        manifest=manifest,
        evidence=evidence,
        review_verifier=review_verifier,
        screening=screening,
        raw_verifier=raw_verifier,
        pack=published.pack,
        catalog=catalog,
        prepared=prepared,
    )


def _model_payload(
    pack: EvidencePack,
    probability: float,
    *,
    observations: tuple[tuple[str, WearStatus], ...] = (),
    citation_crop_id: str | None = None,
    objective_value: object = _NO_OBJECTIVE_CLAIM,
    objective_kind: ObjectiveFactKind | None = None,
    missing_prosecution_summary: bool = False,
) -> bytes:
    citation_id = citation_crop_id or pack.crops[0].crop_id
    objective_claims: list[dict[str, object]] = []
    if objective_value is not _NO_OBJECTIVE_CLAIM:
        fact = (
            pack.objective_facts[0]
            if objective_kind is None
            else next(fact for fact in pack.objective_facts if fact.kind == objective_kind)
        )
        objective_claims.append(
            {
                "kind": fact.kind.value,
                "value": objective_value,
                "evidence_ref": {
                    "kind": ArtifactKind.OBJECTIVE_FACT.value,
                    "artifact_id": fact.fact_id,
                },
            }
        )
    payload: dict[str, object] = {
        "violation_type": pack.event.violation_type.value,
        "evidence_class": pack.event.evidence_class.value,
        "violation_probability": probability,
        "frame_observations": [
            {
                "crop_id": crop_id,
                "wear_status": wear_status.value,
                "reason_summary": "Synthetic structured observation for workflow testing.",
            }
            for crop_id, wear_status in sorted(observations)
        ],
        "evidence_citations": [
            {
                "evidence_ref": {
                    "kind": ArtifactKind.CROP.value,
                    "artifact_id": citation_id,
                },
                "bbox": None,
                "coordinate_space": None,
            }
        ],
        "objective_claims": objective_claims,
        "prosecution_summary": "Synthetic structured evidence supports this proposal.",
        "rationale_summary": "Only typed fixture fields drive this workflow test.",
    }
    if missing_prosecution_summary:
        payload.pop("prosecution_summary")
    return canonical_bytes(payload)


def _expected_response(
    request: VLMCallRequest,
    fixture: FakeVLMFixture,
) -> VLMResponse:
    raw = fixture.raw_response
    assert raw is not None
    content_sha256 = hashlib.sha256(raw).hexdigest()
    response_id = derive_model_response_id(request.run_id, request.request_id, content_sha256)
    return VLMResponse(
        run_id=request.run_id,
        case_id=request.case_id,
        evidence_pack_id=request.evidence_pack_id,
        evidence_pack_version=request.evidence_pack_version,
        request_id=request.request_id,
        request_sha256=request.request_sha256,
        cache_key=request.cache_key,
        purpose=request.purpose,
        attempt_index=0 if request.purpose == VlmCallPurpose.SCREENING else 1,
        raw_response_ref=f"{request.run_id}/model_responses/{response_id}.json",
        content_sha256=content_sha256,
        size_bytes=len(raw),
        input_tokens=fixture.input_tokens,
        output_tokens=fixture.output_tokens,
        latency_ms=fixture.latency_ms,
        model_manifest_id=request.model_manifest_id,
        manifest_id=request.manifest_id,
    )


def _repair_fixture_map(
    runtime: _Runtime,
    initial_raw: bytes,
    repaired_raw: bytes,
) -> dict[str, FakeVLMFixture]:
    initial_fixture = FakeVLMFixture.response(
        initial_raw,
        input_tokens=13,
        output_tokens=7,
        latency_ms=5,
    )
    original_response = _expected_response(runtime.prepared.request, initial_fixture)
    inspection = inspect_screening_response(
        initial_raw,
        request=runtime.prepared.request,
        response=original_response,
    )
    assert inspection.payload is None
    repair = prepare_structure_repair_request(
        original_request=runtime.prepared.request,
        original_response=original_response,
        inspection=inspection,
        raw_response=initial_raw,
        run_manifest=runtime.manifest,
        catalog=runtime.catalog,
    )
    return {
        runtime.prepared.request.cache_key: initial_fixture,
        repair.request.cache_key: FakeVLMFixture.response(
            repaired_raw,
            input_tokens=17,
            output_tokens=9,
            latency_ms=6,
        ),
    }


def _coordinator(
    runtime: _Runtime,
    store: SecureModelResponseStore,
    fixtures: dict[str, FakeVLMFixture],
) -> tuple[ScreeningCoordinator, _CountingFakeVLM]:
    runtime.raw_verifier.bind(store)
    fake = _CountingFakeVLM(DeterministicFakeVLMClient(fixtures, store))
    return (
        ScreeningCoordinator(
            config=runtime.config,
            evidence_repository=runtime.evidence,
            screening_repository=runtime.screening,
            response_store=store,
            vlm_client=fake,
            prompt_catalog=runtime.catalog,
            prompt_registrar=AppendOnlyRenderedPromptRegistry(),
            procedural_review_verifier=runtime.review_verifier,
        ),
        fake,
    )


def _single_fixture(runtime: _Runtime, raw: bytes) -> dict[str, FakeVLMFixture]:
    return {
        runtime.prepared.request.cache_key: FakeVLMFixture.response(
            raw,
            input_tokens=19,
            output_tokens=11,
            latency_ms=7,
        )
    }


@pytest.mark.parametrize(
    ("probability", "expected_decision", "expected_status"),
    [
        pytest.param(
            0.05, ScreeningDecision.NOT_ESTABLISHED, CaseStatus.READY_FOR_ALERT_POLICY, id="low"
        ),
        pytest.param(
            0.95, ScreeningDecision.ESTABLISHED, CaseStatus.READY_FOR_ALERT_POLICY, id="high"
        ),
        pytest.param(0.50, ScreeningDecision.ESCALATE, CaseStatus.ESCALATED, id="gray"),
    ],
)
def test_presence_threshold_scenarios_use_the_complete_offline_pipeline(
    tmp_path: Path,
    probability: float,
    expected_decision: ScreeningDecision,
    expected_status: CaseStatus,
) -> None:
    runtime = _setup_runtime(tmp_path, EvidenceClass.PRESENCE)
    raw = _model_payload(runtime.pack, probability)

    with SecureWorkspace(
        runtime.workspace_root,
        runtime.config.storage.max_media_bytes,
    ) as workspace:
        store = SecureModelResponseStore(workspace)
        coordinator, fake = _coordinator(runtime, store, _single_fixture(runtime, raw))
        outcome = coordinator.process_case(RUN_ID, runtime.pack.case_id)

    assert outcome.screening_result is not None
    assert outcome.screening_result.decision == expected_decision
    assert outcome.case.case.status == expected_status
    assert len(fake.calls) == 1
    if expected_decision == ScreeningDecision.ESCALATE:
        assert outcome.verdict is None
        assert outcome.procedural_review is None
    else:
        assert outcome.verdict is not None
        assert outcome.procedural_review is not None
        assert outcome.procedural_review.passed


def _absence_observations(
    pack: EvidencePack,
    scenario: str,
) -> tuple[tuple[str, WearStatus], ...]:
    authority = pack.observation_sufficiency_input
    assert authority is not None
    clear_ids = set(authority.clear_crop_ids)
    first_clear = min(clear_ids)
    values: list[tuple[str, WearStatus]] = []
    for crop in pack.temporal_crops:
        if scenario == "all_unclear" or crop.crop_id not in clear_ids:
            status = WearStatus.UNCLEAR
        elif scenario == "clear_worn" and crop.crop_id == first_clear:
            status = WearStatus.WORN
        else:
            status = WearStatus.NOT_WORN
        values.append((crop.crop_id, status))
    return tuple(sorted(values))


@pytest.mark.parametrize(
    ("scenario", "expected_decision", "expected_status", "expected_verdict"),
    [
        pytest.param(
            "clear_worn",
            ScreeningDecision.NOT_ESTABLISHED,
            CaseStatus.READY_FOR_ALERT_POLICY,
            VerdictDecision.NOT_ESTABLISHED,
            id="clear-worn",
        ),
        pytest.param(
            "enough_not_worn",
            ScreeningDecision.ESTABLISHED,
            CaseStatus.READY_FOR_ALERT_POLICY,
            VerdictDecision.ESTABLISHED,
            id="enough-not-worn",
        ),
        pytest.param(
            "all_unclear",
            ScreeningDecision.ESCALATE,
            CaseStatus.ESCALATED,
            None,
            id="all-unclear",
        ),
    ],
)
def test_absence_aggregation_scenarios_respect_pack_observation_authority(
    tmp_path: Path,
    scenario: str,
    expected_decision: ScreeningDecision,
    expected_status: CaseStatus,
    expected_verdict: VerdictDecision | None,
) -> None:
    runtime = _setup_runtime(tmp_path, EvidenceClass.ABSENCE)
    raw = _model_payload(
        runtime.pack,
        0.9,
        observations=_absence_observations(runtime.pack, scenario),
    )

    with SecureWorkspace(
        runtime.workspace_root,
        runtime.config.storage.max_media_bytes,
    ) as workspace:
        store = SecureModelResponseStore(workspace)
        coordinator, fake = _coordinator(runtime, store, _single_fixture(runtime, raw))
        outcome = coordinator.process_case(RUN_ID, runtime.pack.case_id)

    assert outcome.screening_result is not None
    assert outcome.screening_result.decision == expected_decision
    assert outcome.case.case.status == expected_status
    assert len(fake.calls) == 1
    if expected_verdict is None:
        assert outcome.verdict is None
        assert outcome.procedural_review is None
    else:
        assert outcome.verdict is not None
        assert outcome.verdict.decision == expected_verdict
        assert outcome.procedural_review is not None
        assert outcome.procedural_review.passed


def test_unknown_crop_in_failed_attempt_survives_repair_and_is_rejected_by_l5(
    tmp_path: Path,
) -> None:
    runtime = _setup_runtime(tmp_path, EvidenceClass.PRESENCE)
    initial = _model_payload(
        runtime.pack,
        0.95,
        citation_crop_id="f" * 64,
        missing_prosecution_summary=True,
    )
    repaired = _model_payload(runtime.pack, 0.95)
    fixtures = _repair_fixture_map(runtime, initial, repaired)

    with SecureWorkspace(
        runtime.workspace_root,
        runtime.config.storage.max_media_bytes,
    ) as workspace:
        store = SecureModelResponseStore(workspace)
        coordinator, fake = _coordinator(runtime, store, fixtures)
        outcome = coordinator.process_case(RUN_ID, runtime.pack.case_id)

    assert outcome.repair_attempted
    assert [call.purpose for call in fake.calls] == [
        VlmCallPurpose.SCREENING,
        VlmCallPurpose.STRUCTURE_REPAIR,
    ]
    assert outcome.case.case.status == CaseStatus.REWORK_REQUIRED
    assert outcome.verdict is not None
    assert len(outcome.verdict.model_response_refs) == 2
    assert outcome.procedural_review is not None
    assert ProceduralDefectCode.FABRICATED_EVIDENCE_REFERENCE in {
        defect.code for defect in outcome.procedural_review.defects
    }


def test_objective_fact_conflict_is_persisted_as_l5_rework(
    tmp_path: Path,
) -> None:
    runtime = _setup_runtime(tmp_path, EvidenceClass.PRESENCE)
    fact = runtime.pack.objective_facts[0]
    assert isinstance(fact.value, int)
    raw = _model_payload(runtime.pack, 0.95, objective_value=fact.value + 20)

    with SecureWorkspace(
        runtime.workspace_root,
        runtime.config.storage.max_media_bytes,
    ) as workspace:
        store = SecureModelResponseStore(workspace)
        coordinator, _ = _coordinator(runtime, store, _single_fixture(runtime, raw))
        outcome = coordinator.process_case(RUN_ID, runtime.pack.case_id)

    assert outcome.case.case.status == CaseStatus.REWORK_REQUIRED
    assert outcome.procedural_review is not None
    assert ProceduralDefectCode.OBJECTIVE_ASSERTION_CONTRADICTION in {
        defect.code for defect in outcome.procedural_review.defects
    }


def test_objective_person_count_conflict_is_persisted_as_l5_rework(
    tmp_path: Path,
) -> None:
    runtime = _setup_runtime(
        tmp_path,
        EvidenceClass.PRESENCE,
        person_count=2,
    )
    raw = _model_payload(
        runtime.pack,
        0.95,
        objective_value=3,
        objective_kind=ObjectiveFactKind.PERSON_COUNT,
    )

    with SecureWorkspace(
        runtime.workspace_root,
        runtime.config.storage.max_media_bytes,
    ) as workspace:
        store = SecureModelResponseStore(workspace)
        coordinator, fake = _coordinator(runtime, store, _single_fixture(runtime, raw))
        outcome = coordinator.process_case(RUN_ID, runtime.pack.case_id)

    person_count_fact = next(
        fact for fact in runtime.pack.objective_facts if fact.kind == ObjectiveFactKind.PERSON_COUNT
    )
    assert person_count_fact.value == 2
    assert len(fake.calls) == 1
    assert outcome.case.case.status == CaseStatus.REWORK_REQUIRED
    assert outcome.verdict is not None
    assert any(
        claim.kind == ObjectiveFactKind.PERSON_COUNT and claim.value == 3
        for claim in outcome.verdict.objective_claims
    )
    assert outcome.procedural_review is not None
    assert {defect.code for defect in outcome.procedural_review.defects} == {
        ProceduralDefectCode.OBJECTIVE_ASSERTION_CONTRADICTION
    }
    assert (
        runtime.screening.load_procedural_review(
            RUN_ID,
            outcome.procedural_review.review_id,
        )
        == outcome.procedural_review
    )
    with sqlite3.connect(runtime.database) as connection:
        assert tuple(
            connection.execute(
                """
                SELECT code FROM procedural_defects
                WHERE run_id = ? AND review_id = ?
                ORDER BY ordinal
                """,
                (RUN_ID, outcome.procedural_review.review_id),
            )
        ) == ((ProceduralDefectCode.OBJECTIVE_ASSERTION_CONTRADICTION.value,),)


def test_two_malformed_responses_persist_typed_backlog_without_partial_screening(
    tmp_path: Path,
) -> None:
    runtime = _setup_runtime(tmp_path, EvidenceClass.PRESENCE)
    fixtures = _repair_fixture_map(runtime, b"not-json", b"still-not-json")

    with SecureWorkspace(
        runtime.workspace_root,
        runtime.config.storage.max_media_bytes,
    ) as workspace:
        store = SecureModelResponseStore(workspace)
        coordinator, fake = _coordinator(runtime, store, fixtures)
        outcome = coordinator.process_case(RUN_ID, runtime.pack.case_id)

    assert outcome.case.case.status == CaseStatus.BACKLOGGED
    assert outcome.backlog_item is not None
    assert outcome.backlog_item.reason_code == BacklogReasonCode.MODEL_OUTPUT_INVALID
    assert [call.purpose for call in fake.calls] == [
        VlmCallPurpose.SCREENING,
        VlmCallPurpose.STRUCTURE_REPAIR,
    ]
    with sqlite3.connect(runtime.database) as connection:
        parse_statuses = tuple(
            row[0]
            for row in connection.execute(
                "SELECT status FROM model_parse_receipts ORDER BY attempt_index"
            )
        )
        screening_count = int(
            connection.execute("SELECT COUNT(*) FROM screening_results").fetchone()[0]
        )
        usage_rows = tuple(
            connection.execute(
                """
                SELECT case_revision, consumer_kind, consumer_id,
                       input_images, input_pixels, input_tokens, output_tokens,
                       provider_latency_ms, retries, estimated_cost
                FROM model_call_usage_accounting
                ORDER BY retries, request_id
                """
            )
        )
    assert parse_statuses == (
        ModelParseStatus.REPAIR_REQUIRED.value,
        ModelParseStatus.INVALID_FINAL.value,
    )
    assert screening_count == 0
    assert len(usage_rows) == 2
    assert all(row[0] == outcome.case.revision for row in usage_rows)
    assert all(row[1] == ArtifactKind.BACKLOG_ITEM.value for row in usage_rows)
    assert all(row[2] == outcome.backlog_item.item_id for row in usage_rows)
    assert tuple(row[3] for row in usage_rows) == (1, 0)
    assert tuple(row[4] for row in usage_rows) == (
        sum(media.width * media.height for media in runtime.prepared.request.media),
        0,
    )
    assert tuple(row[5] for row in usage_rows) == (13, 17)
    assert tuple(row[6] for row in usage_rows) == (7, 9)
    assert tuple(row[7] for row in usage_rows) == (5, 6)
    assert tuple(row[8] for row in usage_rows) == (0, 1)
    assert outcome.case.case.usage.input_images == 1
    assert outcome.case.case.usage.input_pixels == usage_rows[0][4]
    assert outcome.case.case.usage.input_tokens == 30
    assert outcome.case.case.usage.output_tokens == 16
    assert outcome.case.case.usage.provider_latency_ms == 11
    assert outcome.case.case.usage.retries == 1
    assert outcome.case.case.usage.estimated_cost == pytest.approx(
        sum(float(row[9]) for row in usage_rows)
    )


def test_current_pack_change_after_response_accounts_call_once_in_backlog(
    tmp_path: Path,
) -> None:
    runtime = _setup_runtime(tmp_path, EvidenceClass.PRESENCE)
    raw = _model_payload(runtime.pack, 0.95)
    next_draft_base = _presence_draft(
        runtime.pack.event,
        _frame(runtime.pack.event, runtime.pack.event.trigger_frame),
    )
    next_media_sha256 = sha256_hex(["m3-e2e-current-pack-change", runtime.pack.pack_id])
    next_crop = next_draft_base.focus_crops[0].model_copy(
        update={
            "local_path": f"{RUN_ID}/frames/{next_media_sha256}.png",
            "media_sha256": next_media_sha256,
            "pixel_sha256": sha256_hex(["m3-e2e-current-pack-change-pixels"]),
        }
    )
    next_draft = next_draft_base.model_copy(
        update={
            "version": runtime.pack.version + 1,
            "focus_crops": (next_crop,),
        }
    )

    with SecureWorkspace(
        runtime.workspace_root,
        runtime.config.storage.max_media_bytes,
    ) as workspace:
        store = SecureModelResponseStore(workspace)
        runtime.raw_verifier.bind(store)
        provider = _PublishPackAfterResponseVLM(
            DeterministicFakeVLMClient(_single_fixture(runtime, raw), store),
            runtime.evidence,
            next_draft,
        )
        coordinator = ScreeningCoordinator(
            config=runtime.config,
            evidence_repository=runtime.evidence,
            screening_repository=runtime.screening,
            response_store=store,
            vlm_client=provider,
            prompt_catalog=runtime.catalog,
            prompt_registrar=AppendOnlyRenderedPromptRegistry(),
            procedural_review_verifier=runtime.review_verifier,
        )
        outcome = coordinator.process_case(RUN_ID, runtime.pack.case_id)

    assert len(provider.calls) == 1
    assert outcome.case.case.status == CaseStatus.BACKLOGGED
    assert outcome.backlog_item is not None
    assert outcome.backlog_item.reason_code == BacklogReasonCode.CURRENT_PACK_CHANGED
    assert outcome.screening_result is None
    with sqlite3.connect(runtime.database) as connection:
        rows = tuple(
            connection.execute(
                """
                SELECT case_revision, consumer_kind, consumer_id,
                       input_images, input_pixels, input_tokens, output_tokens,
                       provider_latency_ms, retries, estimated_cost
                FROM model_call_usage_accounting
                """
            )
        )
        assert connection.execute("SELECT COUNT(*) FROM screening_results").fetchone() == (0,)
    assert len(rows) == 1
    row = rows[0]
    assert row[:3] == (
        outcome.case.revision,
        ArtifactKind.BACKLOG_ITEM.value,
        outcome.backlog_item.item_id,
    )
    assert row[3:9] == (1, 20_000, 19, 11, 7, 0)
    assert outcome.case.case.usage.input_images == 1
    assert outcome.case.case.usage.input_pixels == 20_000
    assert outcome.case.case.usage.input_tokens == 19
    assert outcome.case.case.usage.output_tokens == 11
    assert outcome.case.case.usage.provider_latency_ms == 7
    assert outcome.case.case.usage.retries == 0
    assert outcome.case.case.usage.estimated_cost == pytest.approx(float(row[9]))


def test_provider_outage_enters_typed_screening_backlog_offline(tmp_path: Path) -> None:
    runtime = _setup_runtime(tmp_path, EvidenceClass.PRESENCE)
    fixtures = {runtime.prepared.request.cache_key: OUTAGE_FIXTURE}

    with SecureWorkspace(
        runtime.workspace_root,
        runtime.config.storage.max_media_bytes,
    ) as workspace:
        store = SecureModelResponseStore(workspace)
        coordinator, fake = _coordinator(runtime, store, fixtures)
        outcome = coordinator.process_case(RUN_ID, runtime.pack.case_id)

    assert len(fake.calls) == 1
    assert outcome.case.case.status == CaseStatus.BACKLOGGED
    assert outcome.backlog_item is not None
    assert outcome.backlog_item.reason_code == BacklogReasonCode.PROVIDER_UNAVAILABLE
    with sqlite3.connect(runtime.database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM model_responses").fetchone() == (0,)
        assert connection.execute("SELECT COUNT(*) FROM screening_results").fetchone() == (0,)


def test_preseeded_real_cache_is_reverified_and_avoids_provider_recall(
    tmp_path: Path,
) -> None:
    runtime = _setup_runtime(tmp_path, EvidenceClass.PRESENCE)
    raw = _model_payload(runtime.pack, 0.95)
    fixture = _single_fixture(runtime, raw)[runtime.prepared.request.cache_key]

    with SecureWorkspace(
        runtime.workspace_root,
        runtime.config.storage.max_media_bytes,
    ) as workspace:
        store = SecureModelResponseStore(workspace)
        runtime.raw_verifier.bind(store)
        seed_client = DeterministicFakeVLMClient(
            {runtime.prepared.request.cache_key: fixture},
            store,
        )
        response = seed_client.complete(runtime.prepared.request)
        owner_token = "e2e-cache-seed-owner-token-with-thirty-two-bytes"
        runtime.screening.claim_model_call(
            RUN_ID,
            runtime.prepared.request,
            owner_token,
        )
        runtime.screening.complete_model_call(
            RUN_ID,
            runtime.prepared.request,
            response,
            owner_token,
        )

        coordinator, fake = _coordinator(runtime, store, {})
        outcome = coordinator.process_case(RUN_ID, runtime.pack.case_id)

    assert outcome.cache_hit_count == 1
    assert fake.calls == []
    assert outcome.case.case.status == CaseStatus.READY_FOR_ALERT_POLICY
    assert outcome.procedural_review is not None
    assert outcome.procedural_review.passed


def test_tampered_real_cache_backlogs_once_without_provider_or_partial_semantics(
    tmp_path: Path,
) -> None:
    runtime = _setup_runtime(tmp_path, EvidenceClass.PRESENCE)
    raw = _model_payload(runtime.pack, 0.95)
    fixture = _single_fixture(runtime, raw)[runtime.prepared.request.cache_key]

    with SecureWorkspace(
        runtime.workspace_root,
        runtime.config.storage.max_media_bytes,
    ) as workspace:
        store = SecureModelResponseStore(workspace)
        runtime.raw_verifier.bind(store)
        seed_client = DeterministicFakeVLMClient(
            {runtime.prepared.request.cache_key: fixture},
            store,
        )
        response = seed_client.complete(runtime.prepared.request)
        owner_token = "e2e-cache-tamper-owner-token-with-thirty-two-bytes"
        runtime.screening.claim_model_call(
            RUN_ID,
            runtime.prepared.request,
            owner_token,
        )
        runtime.screening.complete_model_call(
            RUN_ID,
            runtime.prepared.request,
            response,
            owner_token,
        )
        store.acknowledge(runtime.prepared.request, response)

        with sqlite3.connect(runtime.database) as connection:
            # Corruption injection only: production writes cannot bypass this
            # append-only trigger.  The disposable E2E database is deliberately
            # damaged to prove that a canonical-index mismatch fails closed.
            connection.execute("DROP TRIGGER model_cache_no_update")
            updated = connection.execute(
                """
                UPDATE model_cache
                SET response_content_sha256 = ?
                WHERE run_id = ? AND cache_key = ?
                """,
                ("0" * 64, RUN_ID, runtime.prepared.request.cache_key),
            )
            assert updated.rowcount == 1
            before = connection.execute(
                """
                SELECT
                    (SELECT COUNT(*) FROM case_versions),
                    (SELECT COUNT(*) FROM audit_entries),
                    (SELECT COUNT(*) FROM backlog_items),
                    (SELECT COUNT(*) FROM backlog_item_versions),
                    (SELECT COUNT(*) FROM screening_results),
                    (SELECT COUNT(*) FROM verdicts),
                    (SELECT COUNT(*) FROM procedural_reviews),
                    (SELECT COUNT(*) FROM model_parse_receipts),
                    (SELECT COUNT(*) FROM parsed_screening_outputs),
                    (SELECT COUNT(*) FROM model_call_usage_accounting)
                """
            ).fetchone()
            assert before is not None

        coordinator, fake = _coordinator(runtime, store, {})
        first = coordinator.process_case(RUN_ID, runtime.pack.case_id)
        second = coordinator.process_case(RUN_ID, runtime.pack.case_id)

    assert fake.calls == []
    assert first.case.case.status == CaseStatus.BACKLOGGED
    assert first.backlog_item is not None
    assert first.backlog_item.reason_code == BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE
    assert first.screening_result is None
    assert first.verdict is None
    assert first.procedural_review is None
    assert second == first

    with sqlite3.connect(runtime.database) as connection:
        after = connection.execute(
            """
            SELECT
                (SELECT COUNT(*) FROM case_versions),
                (SELECT COUNT(*) FROM audit_entries),
                (SELECT COUNT(*) FROM backlog_items),
                (SELECT COUNT(*) FROM backlog_item_versions),
                (SELECT COUNT(*) FROM screening_results),
                (SELECT COUNT(*) FROM verdicts),
                (SELECT COUNT(*) FROM procedural_reviews),
                (SELECT COUNT(*) FROM model_parse_receipts),
                (SELECT COUNT(*) FROM parsed_screening_outputs),
                (SELECT COUNT(*) FROM model_call_usage_accounting)
            """
        ).fetchone()
    assert after is not None
    assert after[:4] == tuple(value + 1 for value in before[:4])
    assert after[4:] == before[4:]


def test_sqlite_reload_preserves_identical_terminal_l5_result(tmp_path: Path) -> None:
    runtime = _setup_runtime(tmp_path, EvidenceClass.PRESENCE)
    raw = _model_payload(runtime.pack, 0.95)

    with SecureWorkspace(
        runtime.workspace_root,
        runtime.config.storage.max_media_bytes,
    ) as workspace:
        store = SecureModelResponseStore(workspace)
        coordinator, _ = _coordinator(runtime, store, _single_fixture(runtime, raw))
        first = coordinator.process_case(RUN_ID, runtime.pack.case_id)
        assert first.procedural_review is not None

        reloaded_evidence = SQLiteEvidenceRepository(
            runtime.database,
            BUSY_TIMEOUT_MS,
            verifier=_VerifiedSyntheticCropStore(),
            clock=_clock,
        )
        reloaded_review_verifier = DeterministicProceduralReviewVerifier(
            runtime.config,
            reloaded_evidence,
        )
        reloaded_screening = SQLiteM3Repository(
            runtime.database,
            BUSY_TIMEOUT_MS,
            clock=_clock,
            current_pack_verifier=reloaded_evidence.verify_current_pack,
            raw_response_verifier=store,
            procedural_review_verifier=reloaded_review_verifier,
        )
        reloaded_fake = _CountingFakeVLM(DeterministicFakeVLMClient({}, store))
        reloaded_coordinator = ScreeningCoordinator(
            config=runtime.config,
            evidence_repository=reloaded_evidence,
            screening_repository=reloaded_screening,
            response_store=store,
            vlm_client=reloaded_fake,
            prompt_catalog=runtime.catalog,
            prompt_registrar=AppendOnlyRenderedPromptRegistry(),
            procedural_review_verifier=reloaded_review_verifier,
        )
        second = reloaded_coordinator.process_case(RUN_ID, runtime.pack.case_id)

    assert second.case == first.case
    assert second.verdict == first.verdict
    assert second.procedural_review == first.procedural_review
    assert second.procedural_review is not None
    assert second.procedural_review.passed
    assert reloaded_fake.calls == []
    assert (
        reloaded_screening.load_procedural_review(
            RUN_ID,
            second.procedural_review.review_id,
        )
        == first.procedural_review
    )
