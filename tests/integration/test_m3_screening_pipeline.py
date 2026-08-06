from __future__ import annotations

import os
import sqlite3
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
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
    AppendOnlyRenderedPromptRegistry,
    DeterministicFakeVLMClient,
    FakeVLMFixture,
)
from labcourt.application.model_parser import parse_screening_response
from labcourt.application.model_response_recovery import ModelCallRecoveryCoordinator
from labcourt.application.procedural_review import DeterministicProceduralReviewVerifier
from labcourt.application.screening_coordinator import ScreeningCoordinator
from labcourt.application.screening_request import (
    PreparedScreeningRequest,
    prepare_screening_request,
)
from labcourt.config_loader import load_config
from labcourt.contracts.backlog import BacklogLeaseIdentity
from labcourt.contracts.canonical import canonical_bytes
from labcourt.contracts.config import AppConfig
from labcourt.contracts.detections import Detection
from labcourt.contracts.enums import (
    ArtifactKind,
    BacklogReasonCode,
    CaseStatus,
    CropSource,
    MediaAccess,
    MediaAvailability,
    MediaType,
    ModelParseStatus,
    PrivacyPolicy,
    PrivacyReasonCode,
    ScreeningDecision,
    VerificationStatus,
    VlmRole,
)
from labcourt.contracts.events import CandidateEvent, derive_case_id
from labcourt.contracts.evidence import (
    Crop,
    EvidencePackDraft,
    PrivacyReceipt,
    TrackSummary,
)
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.model_response_recovery import ModelResponseRecoveryReason
from labcourt.contracts.screening import (
    ModelParseReceipt,
    ScreeningResult,
    VLMCallRequest,
    VLMResponse,
)
from labcourt.contracts.storage import ArtifactRef, ArtifactVerification, ClosureReport
from labcourt.contracts.verdicts import ProceduralReview, Verdict
from labcourt.exceptions import ContractViolation, ProviderUnavailable
from labcourt.ports.evidence_repository import AuditHead, CaseSnapshot
from labcourt.ports.m3_semantics import M3SemanticVerifier
from labcourt.ports.procedural_review import ProceduralReviewVerifier
from labcourt.ports.prompts import PromptCatalog
from labcourt.ports.screening_repository import (
    M3CaseCommit,
    ModelCallClaim,
    ModelCallClaimStatus,
)
from labcourt.ports.vlm import (
    ModelResponseStore,
    ModelResponseStoreError,
    ModelResponseStoreFailureCode,
    RawModelResponseVerifier,
    VLMClient,
)
from labcourt.services.m3 import build_screening_prompt_catalog

ROOT = Path(__file__).parents[2]
FIXTURES = ROOT / "tests" / "fixtures" / "m2"
RUN_ID = "run-01"
BUSY_TIMEOUT_MS = 5_000
RECORDED_AT = datetime(2026, 7, 28, 9, 30, tzinfo=UTC)


class _VerifiedCropStore:
    """Deterministic media verifier used to establish the M2 closure authority."""

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


@dataclass(slots=True)
class _MutableClock:
    value: datetime

    def __call__(self) -> datetime:
        return self.value

    def advance(self, delta: timedelta) -> None:
        self.value += delta


class _RawVerifierBinding:
    """Bind the repository to the real store opened by each integration test."""

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


@dataclass(frozen=True, slots=True)
class _PipelineRuntime:
    config: AppConfig
    manifest: RunManifest
    database: Path
    workspace_root: Path
    evidence: SQLiteEvidenceRepository
    repository: SQLiteM3Repository
    raw_verifier: _RawVerifierBinding
    review_verifier: DeterministicProceduralReviewVerifier
    catalog: PromptCatalog
    prepared: PreparedScreeningRequest
    case_id: str
    raw_response: bytes


@dataclass(frozen=True, slots=True)
class _PersistedScreeningRoots:
    repository: SQLiteM3Repository
    response: VLMResponse
    screening: ScreeningResult
    parse_history: tuple[ModelParseReceipt, ...]
    snapshot: CaseSnapshot
    audit_head: AuditHead
    closure: ClosureReport


class _NoCallVLM:
    def __init__(self) -> None:
        self.calls = 0

    def complete(self, request: VLMCallRequest) -> VLMResponse:
        del request
        self.calls += 1
        raise AssertionError("recovery must not call the provider")


class _BlockingVLM:
    def __init__(self, delegate: DeterministicFakeVLMClient) -> None:
        self._delegate = delegate
        self.entered = threading.Event()
        self.release = threading.Event()
        self._lock = threading.Lock()
        self.calls = 0

    def complete(self, request: VLMCallRequest) -> VLMResponse:
        with self._lock:
            self.calls += 1
        self.entered.set()
        if not self.release.wait(timeout=5):
            raise AssertionError("test provider barrier timed out")
        return self._delegate.complete(request)


class _PublishThenRaiseVLM:
    def __init__(self, delegate: DeterministicFakeVLMClient) -> None:
        self._delegate = delegate
        self.calls = 0

    def complete(self, request: VLMCallRequest) -> VLMResponse:
        self.calls += 1
        self._delegate.complete(request)
        raise ProviderUnavailable("simulated process failure after durable publication")


class _CrashOnAcknowledgeStore:
    def __init__(self, delegate: SecureModelResponseStore) -> None:
        self._delegate = delegate
        self.crashed = False

    def probe_recovery(self, request: VLMCallRequest) -> VLMResponse | None:
        return self._delegate.probe_recovery(request)

    def recover(self, request: VLMCallRequest) -> VLMResponse | None:
        return self._delegate.recover(request)

    def acknowledge(self, request: VLMCallRequest, response: VLMResponse) -> None:
        if not self.crashed:
            self.crashed = True
            raise SystemExit("simulated crash after DB commit before journal ack")
        self._delegate.acknowledge(request, response)

    def verify(self, run_id: str, response: VLMResponse) -> VLMResponse:
        return self._delegate.verify(run_id, response)

    def verify_raw_response(
        self,
        run_id: str,
        request: VLMCallRequest,
        response: VLMResponse,
    ) -> VLMResponse:
        return self._delegate.verify_raw_response(run_id, request, response)

    def read_bytes(self, run_id: str, response: VLMResponse, max_bytes: int) -> bytes:
        return self._delegate.read_bytes(run_id, response, max_bytes)

    def read_json(self, run_id: str, response: VLMResponse, max_bytes: int) -> str:
        return self._delegate.read_json(run_id, response, max_bytes)


class _OrderedAcknowledgeStore(_CrashOnAcknowledgeStore):
    """Force both maintainers past DB/raw verification before journal deletion."""

    def __init__(
        self,
        delegate: SecureModelResponseStore,
        barrier: threading.Barrier,
        acknowledged: threading.Event,
        *,
        leader: bool,
    ) -> None:
        super().__init__(delegate)
        self._barrier = barrier
        self._acknowledged = acknowledged
        self._leader = leader

    def acknowledge(self, request: VLMCallRequest, response: VLMResponse) -> None:
        self._barrier.wait(timeout=5)
        if self._leader:
            try:
                self._delegate.acknowledge(request, response)
            finally:
                self._acknowledged.set()
            return
        if not self._acknowledged.wait(timeout=5):
            raise AssertionError("leader did not acknowledge the journal")
        raise ModelResponseStoreError(ModelResponseStoreFailureCode.RESPONSE_NOT_FOUND)


class _CrashBeforeVerdictRepository(SQLiteM3Repository):
    def commit_verdict_review(
        self,
        run_id: str,
        expected_revision: int,
        expected_audit_head: AuditHead,
        current_pack_closure: ClosureReport,
        verdict: Verdict,
        review: ProceduralReview,
    ) -> M3CaseCommit:
        del (
            run_id,
            expected_revision,
            expected_audit_head,
            current_pack_closure,
            verdict,
            review,
        )
        raise SystemExit("simulated crash with a durable SCREENED Case")


class _WaitingSQLiteM3Repository(SQLiteM3Repository):
    def __init__(
        self,
        database_path: str | Path,
        busy_timeout_ms: int,
        clock: object | None = None,
        *,
        current_pack_verifier: Callable[[str, str], ClosureReport] | None = None,
        raw_response_verifier: RawModelResponseVerifier | None = None,
        procedural_review_verifier: ProceduralReviewVerifier | None = None,
        semantic_verifier: M3SemanticVerifier | None = None,
        waiting: threading.Event,
    ) -> None:
        self._waiting = waiting
        super().__init__(
            database_path,
            busy_timeout_ms,
            clock,
            current_pack_verifier=current_pack_verifier,
            raw_response_verifier=raw_response_verifier,
            procedural_review_verifier=procedural_review_verifier,
            semantic_verifier=semantic_verifier,
        )

    def claim_model_call(
        self,
        run_id: str,
        request: VLMCallRequest,
        owner_token: str,
        backlog_lease: BacklogLeaseIdentity | None = None,
    ) -> ModelCallClaim:
        claim = super().claim_model_call(run_id, request, owner_token, backlog_lease)
        if claim.status == ModelCallClaimStatus.WAITING:
            self._waiting.set()
        return claim


def _clock() -> datetime:
    return RECORDED_AT


def _manifest() -> RunManifest:
    return RunManifest.model_validate_json(
        (FIXTURES / "run-manifest-fake.json").read_text(encoding="utf-8")
    )


def _event() -> CandidateEvent:
    return CandidateEvent.model_validate_json(
        (FIXTURES / "candidate-event-presence.json").read_text(encoding="utf-8")
    )


def _frame() -> FrameRef:
    return FrameRef(
        camera_id="cam-01",
        stream_id="demo-ntsc",
        frame_index=90,
        fps_num=30,
        fps_den=1,
        width=640,
        height=480,
        content_sha256="a" * 64,
    )


def _detection() -> Detection:
    frame = _frame()
    event = _event()
    return Detection(
        detection_id="det-bottle-090",
        frame_id=frame.frame_id,
        label="reagent_bottle",
        bbox=BBoxXYXY(x1=10, y1=20, x2=110, y2=220),
        score=0.92,
        track_ref=event.primary_track_ref,
        model_manifest_id=_manifest().models["detector"].model_manifest_id,
    )


def _draft() -> EvidencePackDraft:
    event = _event()
    frame = _frame()
    frame_ref = ArtifactRef(kind=ArtifactKind.FRAME, artifact_id=frame.frame_id)
    detection_ref = ArtifactRef(
        kind=ArtifactKind.DETECTION,
        artifact_id="det-bottle-090",
    )
    source_refs = tuple(sorted((frame_ref, detection_ref), key=lambda ref: ref.sort_key))
    media_sha256 = "c" * 64
    crop = Crop(
        frame_id=frame.frame_id,
        source=CropSource.DETECTION_FOCUS,
        bbox=BBoxXYXY(x1=10, y1=20, x2=110, y2=220),
        source_refs=source_refs,
        local_path=f"{RUN_ID}/frames/{media_sha256}.png",
        availability=MediaAvailability.AVAILABLE,
        source_media_sha256="a" * 64,
        pixel_sha256="b" * 64,
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
    )
    return EvidencePackDraft(
        run_id=RUN_ID,
        case_id=derive_case_id(event.event_id),
        version=1,
        complete=True,
        event=event,
        key_frame_ids=(frame.frame_id,),
        focus_crops=(crop,),
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


def _valid_model_response(crop_id: str, probability: float = 0.95) -> bytes:
    return canonical_bytes(
        {
            "evidence_citations": [
                {
                    "bbox": None,
                    "coordinate_space": None,
                    "evidence_ref": {
                        "artifact_id": crop_id,
                        "kind": ArtifactKind.CROP.value,
                    },
                }
            ],
            "evidence_class": "PRESENCE",
            "frame_observations": [],
            "objective_claims": [],
            "prosecution_summary": "The cited crop supports the presence finding.",
            "rationale_summary": "Only the structured citation and probability are used.",
            "violation_probability": probability,
            "violation_type": "REAGENT_CONTAINER_OPEN",
        }
    )


def _setup_pipeline_runtime(
    tmp_path: Path,
    *,
    m3_clock: object = _clock,
    repository_type: type[SQLiteM3Repository] = SQLiteM3Repository,
    manifest_override: RunManifest | None = None,
    draft_override: EvidencePackDraft | None = None,
) -> _PipelineRuntime:
    config = load_config(ROOT / "configs" / "demo.yaml")
    manifest = manifest_override or _manifest()
    database = tmp_path / "labcourt.sqlite3"
    workspace_root = tmp_path / "workspace"
    workspace_root.mkdir()
    MigrationRunner(database, BUSY_TIMEOUT_MS, clock=_clock).apply_all()
    evidence = SQLiteEvidenceRepository(
        database,
        BUSY_TIMEOUT_MS,
        verifier=_VerifiedCropStore(),
        clock=_clock,
    )
    evidence.register_run(RUN_ID, manifest)
    evidence.register_frame(RUN_ID, _frame())
    evidence.register_detection(RUN_ID, _detection())
    draft = draft_override or _draft()
    evidence.create_or_get_case(RUN_ID, draft.event)
    published = evidence.publish_pack(RUN_ID, 1, draft)
    review_verifier = DeterministicProceduralReviewVerifier(config, evidence)
    raw_verifier = _RawVerifierBinding()
    repository = repository_type(
        database,
        BUSY_TIMEOUT_MS,
        clock=m3_clock,
        current_pack_verifier=evidence.verify_current_pack,
        raw_response_verifier=raw_verifier,
        procedural_review_verifier=review_verifier,
    )
    catalog = build_screening_prompt_catalog(manifest)
    prepared = prepare_screening_request(published.pack, config, manifest, catalog)
    return _PipelineRuntime(
        config=config,
        manifest=manifest,
        database=database,
        workspace_root=workspace_root,
        evidence=evidence,
        repository=repository,
        raw_verifier=raw_verifier,
        review_verifier=review_verifier,
        catalog=catalog,
        prepared=prepared,
        case_id=published.pack.case_id,
        raw_response=_valid_model_response(published.pack.focus_crops[0].crop_id),
    )


def _pipeline_coordinator(
    runtime: _PipelineRuntime,
    *,
    response_store: ModelResponseStore,
    client: VLMClient,
    repository: SQLiteM3Repository | None = None,
) -> ScreeningCoordinator:
    runtime.raw_verifier.bind(response_store)
    return ScreeningCoordinator(
        config=runtime.config,
        evidence_repository=runtime.evidence,
        screening_repository=repository or runtime.repository,
        response_store=response_store,
        vlm_client=client,
        prompt_catalog=runtime.catalog,
        prompt_registrar=AppendOnlyRenderedPromptRegistry(),
        procedural_review_verifier=runtime.review_verifier,
    )


def _persist_real_screening_roots(
    runtime: _PipelineRuntime,
    store: SecureModelResponseStore,
    *,
    probability: float = 0.95,
) -> _PersistedScreeningRoots:
    repository = SQLiteM3Repository(
        runtime.database,
        BUSY_TIMEOUT_MS,
        clock=_clock,
        current_pack_verifier=runtime.evidence.verify_current_pack,
        raw_response_verifier=store,
        procedural_review_verifier=runtime.review_verifier,
    )
    request = runtime.prepared.request
    pack = runtime.evidence.load_pack(RUN_ID, request.evidence_pack_id)
    raw = _valid_model_response(pack.focus_crops[0].crop_id, probability)
    response = store.publish(
        request,
        raw,
        input_tokens=23,
        output_tokens=11,
        latency_ms=17,
    )
    owner_token = "physical-closure-owner-token-with-thirty-two-bytes"
    claim = repository.claim_model_call(RUN_ID, request, owner_token)
    assert claim.status == ModelCallClaimStatus.ACQUIRED
    repository.complete_model_call(RUN_ID, request, response, owner_token)
    store.acknowledge(request, response)
    parsed = parse_screening_response(raw, request=request, response=response)
    assert parsed.output is not None
    repository.append_parse_receipt(parsed.receipt, parsed.output)
    screening = runtime.review_verifier.rebuild_screening(
        parsed.output,
        pack,
        1,
    )
    snapshot = runtime.evidence.load_case(RUN_ID, runtime.case_id)
    return _PersistedScreeningRoots(
        repository=repository,
        response=response,
        screening=screening,
        parse_history=(parsed.receipt,),
        snapshot=snapshot,
        audit_head=runtime.evidence.get_audit_head(RUN_ID),
        closure=runtime.evidence.verify_current_pack(RUN_ID, pack.pack_id),
    )


def _table_counts(database: Path) -> tuple[int, ...]:
    tables = (
        "model_responses",
        "model_cache",
        "parsed_screening_outputs",
        "model_parse_receipts",
        "screening_results",
        "verdicts",
        "procedural_reviews",
        "procedural_defects",
    )
    with sqlite3.connect(database) as connection:
        return tuple(
            int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            for table in tables
        )


def _row_counts(database: Path, *tables: str) -> tuple[int, ...]:
    with sqlite3.connect(database) as connection:
        return tuple(
            int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            for table in tables
        )


def _damage_raw_response(
    workspace_root: Path,
    response: VLMResponse,
    damage: str,
    *,
    link_source: Path | None = None,
) -> None:
    response_path = workspace_root / response.raw_response_ref
    if damage == "missing":
        response_path.unlink()
        return
    if damage == "tampered":
        response_path.write_bytes(b"tampered")
        return
    if link_source is None:
        raise AssertionError("link damage requires a source path")
    response_path.replace(link_source)
    try:
        if damage == "hardlink":
            os.link(link_source, response_path)
        elif damage == "symlink":
            os.symlink(link_source, response_path)
        else:
            raise AssertionError(f"unsupported raw response damage: {damage}")
    except OSError as error:
        pytest.skip(f"{damage} creation is unavailable on this platform: {error}")


def test_real_sqlite_store_and_fake_vlm_complete_m3_chain_idempotently(
    tmp_path: Path,
) -> None:
    config = load_config(ROOT / "configs" / "demo.yaml")
    manifest = _manifest()
    database = tmp_path / "labcourt.sqlite3"
    workspace_root = tmp_path / "workspace"
    workspace_root.mkdir()
    MigrationRunner(database, BUSY_TIMEOUT_MS, clock=_clock).apply_all()

    evidence = SQLiteEvidenceRepository(
        database,
        BUSY_TIMEOUT_MS,
        verifier=_VerifiedCropStore(),
        clock=_clock,
    )
    evidence.register_run(RUN_ID, manifest)
    evidence.register_frame(RUN_ID, _frame())
    evidence.register_detection(RUN_ID, _detection())
    evidence.create_or_get_case(RUN_ID, _event())
    published = evidence.publish_pack(RUN_ID, 1, _draft())
    assert published.case.case.status == CaseStatus.EVIDENCE_READY

    review_verifier = DeterministicProceduralReviewVerifier(config, evidence)
    raw_verifier = _RawVerifierBinding()
    repository = SQLiteM3Repository(
        database,
        BUSY_TIMEOUT_MS,
        clock=_clock,
        current_pack_verifier=evidence.verify_current_pack,
        raw_response_verifier=raw_verifier,
        procedural_review_verifier=review_verifier,
    )
    catalog = build_screening_prompt_catalog(manifest)
    prepared = prepare_screening_request(published.pack, config, manifest, catalog)
    raw_response = _valid_model_response(published.pack.focus_crops[0].crop_id)
    audit_before = evidence.get_audit_head(RUN_ID)

    with SecureWorkspace(workspace_root, config.storage.max_media_bytes) as workspace:
        response_store = SecureModelResponseStore(workspace)
        raw_verifier.bind(response_store)
        fake = _CountingFakeVLM(
            DeterministicFakeVLMClient(
                {
                    prepared.request.cache_key: FakeVLMFixture.response(
                        raw_response,
                        input_tokens=23,
                        output_tokens=11,
                        latency_ms=17,
                    )
                },
                response_store,
            )
        )
        coordinator = ScreeningCoordinator(
            config=config,
            evidence_repository=evidence,
            screening_repository=repository,
            response_store=response_store,
            vlm_client=fake,
            prompt_catalog=catalog,
            prompt_registrar=AppendOnlyRenderedPromptRegistry(),
            procedural_review_verifier=review_verifier,
        )

        first = coordinator.process_case(RUN_ID, published.pack.case_id)

        assert first.case.case.status == CaseStatus.READY_FOR_ALERT_POLICY
        assert first.screening_result is not None
        assert first.verdict is not None
        assert first.procedural_review is not None
        assert first.procedural_review.passed
        assert first.procedural_review.defects == ()
        assert first.case.revision == published.case.revision + 2
        assert first.case.case.timeline[-2].stage == "SCREENING"
        assert first.case.case.timeline[-1].stage == "PROCEDURAL_GATE"
        assert first.case.case.usage.input_images == 1
        assert first.case.case.usage.input_pixels == 20_000
        assert first.case.case.usage.input_tokens == 23
        assert first.case.case.usage.output_tokens == 11
        assert first.case.case.usage.provider_latency_ms == 17
        assert len(fake.calls) == 1

        parsed = first.screening_result.parsed_output
        persisted_response = repository.load_raw_response(RUN_ID, parsed.response_id)
        assert response_store.verify(RUN_ID, persisted_response) == persisted_response
        assert (
            response_store.read_bytes(
                RUN_ID,
                persisted_response,
                prepared.request.budget.max_response_bytes,
            )
            == raw_response
        )
        cached = repository.get(RUN_ID, prepared.request)
        assert cached is not None
        assert cached.response == persisted_response
        assert cached.entry.request_id == prepared.request.request_id
        receipt = repository.load_parse_receipt_for_output(
            RUN_ID,
            parsed.parsed_output_id,
        )
        assert receipt.status == ModelParseStatus.PARSED
        assert receipt.response_id == persisted_response.response_id
        assert first.verdict.model_response_refs == (
            ArtifactRef(
                kind=ArtifactKind.MODEL_RESPONSE,
                artifact_id=persisted_response.response_id,
            ),
        )
        assert repository.load_parsed_output(RUN_ID, parsed.parsed_output_id) == parsed
        assert repository.load_screening(RUN_ID, first.screening_result.screening_id) == (
            first.screening_result
        )
        assert repository.load_verdict(RUN_ID, first.verdict.verdict_id) == first.verdict
        assert (
            repository.load_procedural_review(
                RUN_ID,
                first.procedural_review.review_id,
            )
            == first.procedural_review
        )

        expected_counts = (1, 1, 1, 1, 1, 1, 1, 0)
        assert _table_counts(database) == expected_counts
        audit_after_first = evidence.get_audit_head(RUN_ID)
        assert audit_after_first.sequence == audit_before.sequence + 2

        second = coordinator.process_case(RUN_ID, published.pack.case_id)

        assert second.case == first.case
        assert second.screening_result == first.screening_result
        assert second.verdict == first.verdict
        assert second.procedural_review == first.procedural_review
        assert len(fake.calls) == 1
        assert _table_counts(database) == expected_counts
        assert evidence.get_audit_head(RUN_ID) == audit_after_first

    with sqlite3.connect(database) as connection:
        statuses = tuple(
            row[0]
            for row in connection.execute(
                """
                SELECT status FROM case_versions
                WHERE run_id = ? AND case_id = ?
                ORDER BY revision
                """,
                (RUN_ID, published.pack.case_id),
            )
        )
        audit_tail = tuple(
            connection.execute(
                """
                SELECT object_kind, action FROM audit_entries
                WHERE run_id = ? AND sequence > ?
                ORDER BY sequence
                """,
                (RUN_ID, audit_before.sequence),
            )
        )
        screening_audit_row = connection.execute(
            "SELECT audit_sequence FROM screening_results WHERE run_id = ?",
            (RUN_ID,),
        ).fetchone()
        verdict_review_audit_row = connection.execute(
            """
            SELECT v.audit_sequence, pr.audit_sequence
            FROM verdicts AS v
            JOIN procedural_reviews AS pr
              ON pr.run_id = v.run_id
             AND pr.reviewed_verdict_id = v.verdict_id
            WHERE v.run_id = ?
            """,
            (RUN_ID,),
        ).fetchone()

    assert statuses[-3:] == (
        CaseStatus.EVIDENCE_READY.value,
        CaseStatus.SCREENED.value,
        CaseStatus.READY_FOR_ALERT_POLICY.value,
    )
    assert audit_tail == (
        (ArtifactKind.SCREENING_RESULT.value, "CASE_STATE_CHANGED"),
        (ArtifactKind.PROCEDURAL_REVIEW.value, "CASE_STATE_CHANGED"),
    )
    assert screening_audit_row == (audit_before.sequence + 1,)
    assert verdict_review_audit_row == (
        audit_before.sequence + 2,
        audit_before.sequence + 2,
    )


def test_two_sqlite_workers_share_one_durable_model_call(
    tmp_path: Path,
) -> None:
    runtime = _setup_pipeline_runtime(tmp_path)
    waiting = threading.Event()
    waiter_repository = _WaitingSQLiteM3Repository(
        runtime.database,
        BUSY_TIMEOUT_MS,
        clock=_clock,
        current_pack_verifier=runtime.evidence.verify_current_pack,
        raw_response_verifier=runtime.raw_verifier,
        procedural_review_verifier=runtime.review_verifier,
        waiting=waiting,
    )

    with SecureWorkspace(
        runtime.workspace_root,
        runtime.config.storage.max_media_bytes,
    ) as workspace:
        response_store = SecureModelResponseStore(workspace)
        provider = _BlockingVLM(
            DeterministicFakeVLMClient(
                {
                    runtime.prepared.request.cache_key: FakeVLMFixture.response(
                        runtime.raw_response,
                        input_tokens=23,
                        output_tokens=11,
                        latency_ms=17,
                    )
                },
                response_store,
            )
        )
        first_coordinator = _pipeline_coordinator(
            runtime,
            response_store=response_store,
            client=provider,
        )
        second_coordinator = _pipeline_coordinator(
            runtime,
            response_store=response_store,
            client=provider,
            repository=waiter_repository,
        )
        with ThreadPoolExecutor(max_workers=2) as executor:
            first_future = executor.submit(
                first_coordinator.process_case,
                RUN_ID,
                runtime.case_id,
            )
            assert provider.entered.wait(timeout=5)
            second_future = executor.submit(
                second_coordinator._controlled_call,
                runtime.prepared.request,
                VlmRole.SCREENING,
            )
            assert waiting.wait(timeout=5)
            provider.release.set()
            first = first_future.result(timeout=10)
            second_call = second_future.result(timeout=10)

    assert provider.calls == 1
    assert first.case.case.status == CaseStatus.READY_FOR_ALERT_POLICY
    assert first.screening_result is not None
    second_parse = parse_screening_response(
        second_call.raw_bytes,
        request=runtime.prepared.request,
        response=second_call.response,
    )
    assert second_parse.output == first.screening_result.parsed_output
    with sqlite3.connect(runtime.database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM model_call_claims").fetchone() == (1,)
        assert connection.execute("SELECT COUNT(*) FROM model_responses").fetchone() == (1,)
        assert connection.execute(
            "SELECT COUNT(*) FROM model_call_usage_accounting"
        ).fetchone() == (1,)


def test_journaled_publication_survives_provider_raise_and_expired_claim_completion(
    tmp_path: Path,
) -> None:
    mutable_clock = _MutableClock(RECORDED_AT)
    runtime = _setup_pipeline_runtime(tmp_path, m3_clock=mutable_clock)
    with SecureWorkspace(
        runtime.workspace_root,
        runtime.config.storage.max_media_bytes,
    ) as workspace:
        response_store = SecureModelResponseStore(workspace)
        publisher = DeterministicFakeVLMClient(
            {
                runtime.prepared.request.cache_key: FakeVLMFixture.response(
                    runtime.raw_response,
                    input_tokens=23,
                    output_tokens=11,
                    latency_ms=17,
                )
            },
            response_store,
        )
        failed_provider = _PublishThenRaiseVLM(publisher)
        first = _pipeline_coordinator(
            runtime,
            response_store=response_store,
            client=failed_provider,
        )
        with pytest.raises(ProviderUnavailable):
            first.process_case(RUN_ID, runtime.case_id)

        assert runtime.evidence.load_case(RUN_ID, runtime.case_id).case.status == (
            CaseStatus.EVIDENCE_READY
        )
        assert response_store.recover(runtime.prepared.request) is not None
        with sqlite3.connect(runtime.database) as connection:
            assert connection.execute("SELECT status FROM model_call_claims").fetchone() == (
                "ACTIVE",
            )
            assert connection.execute("SELECT COUNT(*) FROM model_responses").fetchone() == (0,)

        mutable_clock.advance(
            timedelta(seconds=runtime.prepared.request.budget.claim_lease_seconds + 1)
        )
        maintenance = ModelCallRecoveryCoordinator(
            runtime.repository,
            response_store,
        ).recover(RUN_ID, mutable_clock())
        assert maintenance.items[0].disposition.value == "ACKNOWLEDGED"
        no_call = _NoCallVLM()
        recovered = _pipeline_coordinator(
            runtime,
            response_store=response_store,
            client=no_call,
        ).process_case(RUN_ID, runtime.case_id)

        assert recovered.case.case.status == CaseStatus.READY_FOR_ALERT_POLICY
        assert no_call.calls == 0
        assert response_store.recover(runtime.prepared.request) is None
        with sqlite3.connect(runtime.database) as connection:
            assert connection.execute(
                "SELECT status, takeover_count FROM model_call_claims"
            ).fetchone() == ("COMPLETED", 0)


def test_two_maintenance_processes_converge_one_journal_without_provider_call(
    tmp_path: Path,
) -> None:
    mutable_clock = _MutableClock(RECORDED_AT)
    runtime = _setup_pipeline_runtime(tmp_path, m3_clock=mutable_clock)
    with SecureWorkspace(
        runtime.workspace_root,
        runtime.config.storage.max_media_bytes,
    ) as publishing_workspace:
        publishing_store = SecureModelResponseStore(publishing_workspace)
        publisher = DeterministicFakeVLMClient(
            {
                runtime.prepared.request.cache_key: FakeVLMFixture.response(
                    runtime.raw_response,
                    input_tokens=23,
                    output_tokens=11,
                    latency_ms=17,
                )
            },
            publishing_store,
        )
        failed_provider = _PublishThenRaiseVLM(publisher)
        with pytest.raises(ProviderUnavailable):
            _pipeline_coordinator(
                runtime,
                response_store=publishing_store,
                client=failed_provider,
            ).process_case(RUN_ID, runtime.case_id)

    assert failed_provider.calls == 1
    mutable_clock.advance(
        timedelta(seconds=runtime.prepared.request.budget.claim_lease_seconds + 1)
    )
    with (
        SecureWorkspace(
            runtime.workspace_root,
            runtime.config.storage.max_media_bytes,
        ) as first_workspace,
        SecureWorkspace(
            runtime.workspace_root,
            runtime.config.storage.max_media_bytes,
        ) as second_workspace,
    ):
        first_store = SecureModelResponseStore(first_workspace)
        second_store = SecureModelResponseStore(second_workspace)
        acknowledge_barrier = threading.Barrier(2)
        acknowledged = threading.Event()
        recovery_stores = (
            _OrderedAcknowledgeStore(
                first_store,
                acknowledge_barrier,
                acknowledged,
                leader=True,
            ),
            _OrderedAcknowledgeStore(
                second_store,
                acknowledge_barrier,
                acknowledged,
                leader=False,
            ),
        )
        repositories = (
            SQLiteM3Repository(
                runtime.database,
                BUSY_TIMEOUT_MS,
                clock=mutable_clock,
                raw_response_verifier=recovery_stores[0],
            ),
            SQLiteM3Repository(
                runtime.database,
                BUSY_TIMEOUT_MS,
                clock=mutable_clock,
                raw_response_verifier=recovery_stores[1],
            ),
        )
        coordinators = (
            ModelCallRecoveryCoordinator(repositories[0], recovery_stores[0]),
            ModelCallRecoveryCoordinator(repositories[1], recovery_stores[1]),
        )
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = tuple(
                executor.submit(coordinator.recover, RUN_ID, mutable_clock())
                for coordinator in coordinators
            )
            results = tuple(future.result(timeout=10) for future in futures)

        assert all(
            result.items[0].reason_code == ModelResponseRecoveryReason.JOURNAL_ACKNOWLEDGED
            for result in results
        )
        assert first_store.recover(runtime.prepared.request) is None

    assert failed_provider.calls == 1
    with sqlite3.connect(runtime.database) as connection:
        assert connection.execute(
            "SELECT status, takeover_count FROM model_call_claims"
        ).fetchone() == ("COMPLETED", 0)
        assert connection.execute("SELECT COUNT(*) FROM model_responses").fetchone() == (1,)
        assert connection.execute("SELECT COUNT(*) FROM model_cache").fetchone() == (1,)


def test_completed_db_publication_is_recovered_before_journal_ack(
    tmp_path: Path,
) -> None:
    runtime = _setup_pipeline_runtime(tmp_path)
    with SecureWorkspace(
        runtime.workspace_root,
        runtime.config.storage.max_media_bytes,
    ) as workspace:
        response_store = SecureModelResponseStore(workspace)
        crashing_store = _CrashOnAcknowledgeStore(response_store)
        provider = DeterministicFakeVLMClient(
            {
                runtime.prepared.request.cache_key: FakeVLMFixture.response(
                    runtime.raw_response,
                    input_tokens=23,
                    output_tokens=11,
                    latency_ms=17,
                )
            },
            response_store,
        )
        coordinator = _pipeline_coordinator(
            runtime,
            response_store=crashing_store,
            client=provider,
        )
        with pytest.raises(SystemExit, match="after DB commit"):
            coordinator.process_case(RUN_ID, runtime.case_id)

        with sqlite3.connect(runtime.database) as connection:
            assert connection.execute("SELECT status FROM model_call_claims").fetchone() == (
                "COMPLETED",
            )
            assert connection.execute("SELECT COUNT(*) FROM model_cache").fetchone() == (1,)
        assert response_store.recover(runtime.prepared.request) is not None

        no_call = _NoCallVLM()
        recovered = _pipeline_coordinator(
            runtime,
            response_store=response_store,
            client=no_call,
        ).process_case(RUN_ID, runtime.case_id)
        assert recovered.case.case.status == CaseStatus.READY_FOR_ALERT_POLICY
        assert no_call.calls == 0
        assert response_store.recover(runtime.prepared.request) is None


@pytest.mark.parametrize("damage", ["missing", "tampered"])
def test_screened_resume_raw_integrity_failure_backlogs_without_verdict(
    tmp_path: Path,
    damage: str,
) -> None:
    runtime = _setup_pipeline_runtime(
        tmp_path,
        repository_type=_CrashBeforeVerdictRepository,
    )
    with SecureWorkspace(
        runtime.workspace_root,
        runtime.config.storage.max_media_bytes,
    ) as workspace:
        response_store = SecureModelResponseStore(workspace)
        provider = DeterministicFakeVLMClient(
            {
                runtime.prepared.request.cache_key: FakeVLMFixture.response(
                    runtime.raw_response,
                    input_tokens=23,
                    output_tokens=11,
                    latency_ms=17,
                )
            },
            response_store,
        )
        with pytest.raises(SystemExit, match="durable SCREENED"):
            _pipeline_coordinator(
                runtime,
                response_store=response_store,
                client=provider,
            ).process_case(RUN_ID, runtime.case_id)

        screened = runtime.evidence.load_case(RUN_ID, runtime.case_id)
        assert screened.case.status == CaseStatus.SCREENED
        parsed = screened.case.screening_results[-1].parsed_output
        response = runtime.repository.load_raw_response(RUN_ID, parsed.response_id)
        response_path = runtime.workspace_root / response.raw_response_ref
        if damage == "missing":
            response_path.unlink()
        else:
            response_path.write_bytes(b"tampered")

        normal_repository = SQLiteM3Repository(
            runtime.database,
            BUSY_TIMEOUT_MS,
            clock=_clock,
            current_pack_verifier=runtime.evidence.verify_current_pack,
            raw_response_verifier=response_store,
            procedural_review_verifier=runtime.review_verifier,
        )
        no_call = _NoCallVLM()
        outcome = _pipeline_coordinator(
            runtime,
            response_store=response_store,
            client=no_call,
            repository=normal_repository,
        ).process_case(RUN_ID, runtime.case_id)

    assert outcome.case.case.status == CaseStatus.BACKLOGGED
    assert outcome.backlog_item is not None
    assert outcome.backlog_item.reason_code == BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE
    assert outcome.verdict is None
    assert no_call.calls == 0
    assert outcome.case.case.usage.input_tokens == 23
    with sqlite3.connect(runtime.database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM verdicts").fetchone() == (0,)
        assert connection.execute("SELECT COUNT(*) FROM procedural_reviews").fetchone() == (0,)
        assert connection.execute(
            "SELECT COUNT(*) FROM model_call_usage_accounting"
        ).fetchone() == (1,)


def test_complete_model_call_rejects_missing_physical_response_without_partial_writes(
    tmp_path: Path,
) -> None:
    runtime = _setup_pipeline_runtime(tmp_path)
    request = runtime.prepared.request
    tracked = (
        "model_responses",
        "model_cache",
        "case_versions",
        "audit_entries",
        "model_call_usage_accounting",
    )
    before = _row_counts(runtime.database, *tracked)
    case_before = runtime.evidence.load_case(RUN_ID, runtime.case_id)
    head_before = runtime.evidence.get_audit_head(RUN_ID)

    with SecureWorkspace(
        runtime.workspace_root,
        runtime.config.storage.max_media_bytes,
    ) as workspace:
        store = SecureModelResponseStore(workspace)
        repository = SQLiteM3Repository(
            runtime.database,
            BUSY_TIMEOUT_MS,
            clock=_clock,
            current_pack_verifier=runtime.evidence.verify_current_pack,
            raw_response_verifier=store,
            procedural_review_verifier=runtime.review_verifier,
        )
        response = store.publish(request, runtime.raw_response)
        _damage_raw_response(runtime.workspace_root, response, "missing")
        owner_token = "missing-response-owner-token-with-thirty-two-bytes"
        repository.claim_model_call(RUN_ID, request, owner_token)

        with pytest.raises(ModelResponseStoreError) as rejected:
            repository.complete_model_call(RUN_ID, request, response, owner_token)

    assert rejected.value.reason_code == ModelResponseStoreFailureCode.RESPONSE_NOT_FOUND
    assert _row_counts(runtime.database, *tracked) == before
    assert runtime.evidence.load_case(RUN_ID, runtime.case_id) == case_before
    assert runtime.evidence.get_audit_head(RUN_ID) == head_before
    with sqlite3.connect(runtime.database) as connection:
        assert connection.execute(
            """
            SELECT status, response_id, completed_at
            FROM model_call_claims WHERE run_id = ? AND request_id = ?
            """,
            (RUN_ID, request.request_id),
        ).fetchone() == ("ACTIVE", None, None)


def test_parse_receipt_replay_rejects_missing_raw_without_partial_writes(
    tmp_path: Path,
) -> None:
    runtime = _setup_pipeline_runtime(tmp_path)
    tracked = (
        "parsed_screening_outputs",
        "model_parse_receipts",
        "procedural_defects",
        "case_versions",
        "audit_entries",
        "model_call_usage_accounting",
    )
    with SecureWorkspace(
        runtime.workspace_root,
        runtime.config.storage.max_media_bytes,
    ) as workspace:
        store = SecureModelResponseStore(workspace)
        roots = _persist_real_screening_roots(runtime, store)
        before = _row_counts(runtime.database, *tracked)
        case_before = runtime.evidence.load_case(RUN_ID, runtime.case_id)
        head_before = runtime.evidence.get_audit_head(RUN_ID)
        _damage_raw_response(runtime.workspace_root, roots.response, "missing")

        with pytest.raises(ModelResponseStoreError) as rejected:
            roots.repository.append_parse_receipt(
                roots.parse_history[0],
                roots.screening.parsed_output,
            )

    assert rejected.value.reason_code == ModelResponseStoreFailureCode.RESPONSE_NOT_FOUND
    assert _row_counts(runtime.database, *tracked) == before
    assert runtime.evidence.load_case(RUN_ID, runtime.case_id) == case_before
    assert runtime.evidence.get_audit_head(RUN_ID) == head_before


@pytest.mark.parametrize(
    ("probability", "expected_decision"),
    [
        (0.95, ScreeningDecision.ESTABLISHED),
        (0.50, ScreeningDecision.ESCALATE),
    ],
)
@pytest.mark.parametrize(
    ("damage", "expected_failure"),
    [
        ("missing", ModelResponseStoreFailureCode.RESPONSE_NOT_FOUND),
        ("tampered", ModelResponseStoreFailureCode.RESPONSE_INTEGRITY_FAILURE),
    ],
)
def test_screening_commit_rechecks_raw_and_rolls_back_every_route(
    tmp_path: Path,
    probability: float,
    expected_decision: ScreeningDecision,
    damage: str,
    expected_failure: ModelResponseStoreFailureCode,
) -> None:
    runtime = _setup_pipeline_runtime(tmp_path)
    tracked = (
        "screening_results",
        "case_versions",
        "audit_entries",
        "model_call_usage_accounting",
    )
    with SecureWorkspace(
        runtime.workspace_root,
        runtime.config.storage.max_media_bytes,
    ) as workspace:
        store = SecureModelResponseStore(workspace)
        roots = _persist_real_screening_roots(
            runtime,
            store,
            probability=probability,
        )
        assert roots.screening.decision == expected_decision
        before = _row_counts(runtime.database, *tracked)
        _damage_raw_response(runtime.workspace_root, roots.response, damage)

        with pytest.raises(ModelResponseStoreError) as rejected:
            roots.repository.commit_screening(
                RUN_ID,
                roots.snapshot.revision,
                roots.audit_head,
                roots.closure,
                roots.screening,
            )

    assert rejected.value.reason_code == expected_failure
    assert _row_counts(runtime.database, *tracked) == before
    assert runtime.evidence.load_case(RUN_ID, runtime.case_id) == roots.snapshot
    assert runtime.evidence.get_audit_head(RUN_ID) == roots.audit_head


@pytest.mark.parametrize("damage", ["hardlink", "symlink"])
def test_screening_commit_rejects_linked_raw_response_when_supported(
    tmp_path: Path,
    damage: str,
) -> None:
    runtime = _setup_pipeline_runtime(tmp_path)
    tracked = (
        "screening_results",
        "case_versions",
        "audit_entries",
        "model_call_usage_accounting",
    )
    with SecureWorkspace(
        runtime.workspace_root,
        runtime.config.storage.max_media_bytes,
    ) as workspace:
        store = SecureModelResponseStore(workspace)
        roots = _persist_real_screening_roots(runtime, store)
        before = _row_counts(runtime.database, *tracked)
        _damage_raw_response(
            runtime.workspace_root,
            roots.response,
            damage,
            link_source=tmp_path / f"{damage}-raw-source.json",
        )

        with pytest.raises(ModelResponseStoreError) as rejected:
            roots.repository.commit_screening(
                RUN_ID,
                roots.snapshot.revision,
                roots.audit_head,
                roots.closure,
                roots.screening,
            )

    assert rejected.value.reason_code in {
        ModelResponseStoreFailureCode.RESPONSE_INTEGRITY_FAILURE,
        ModelResponseStoreFailureCode.WORKSPACE_REJECTED,
    }
    assert _row_counts(runtime.database, *tracked) == before
    assert runtime.evidence.load_case(RUN_ID, runtime.case_id) == roots.snapshot
    assert runtime.evidence.get_audit_head(RUN_ID) == roots.audit_head


@pytest.mark.parametrize(
    ("damage", "expected_failure"),
    [
        ("missing", ModelResponseStoreFailureCode.RESPONSE_NOT_FOUND),
        ("tampered", ModelResponseStoreFailureCode.RESPONSE_INTEGRITY_FAILURE),
    ],
)
def test_verdict_review_commit_rechecks_raw_and_rolls_back_atomically(
    tmp_path: Path,
    damage: str,
    expected_failure: ModelResponseStoreFailureCode,
) -> None:
    runtime = _setup_pipeline_runtime(tmp_path)
    tracked = (
        "verdicts",
        "procedural_reviews",
        "procedural_defects",
        "case_versions",
        "audit_entries",
        "model_call_usage_accounting",
    )
    with SecureWorkspace(
        runtime.workspace_root,
        runtime.config.storage.max_media_bytes,
    ) as workspace:
        store = SecureModelResponseStore(workspace)
        roots = _persist_real_screening_roots(runtime, store)
        screening_commit = roots.repository.commit_screening(
            RUN_ID,
            roots.snapshot.revision,
            roots.audit_head,
            roots.closure,
            roots.screening,
        )
        assert screening_commit.case.case.status == CaseStatus.SCREENED
        pack = runtime.evidence.load_pack(RUN_ID, roots.response.evidence_pack_id)
        response_refs = tuple(
            sorted(
                (
                    ArtifactRef(
                        kind=ArtifactKind.MODEL_RESPONSE,
                        artifact_id=receipt.response_id,
                    )
                    for receipt in roots.parse_history
                ),
                key=lambda ref: ref.sort_key,
            )
        )
        verdict = runtime.review_verifier.rebuild_fast_verdict(
            roots.screening,
            pack,
            response_refs,
            1,
        )
        review = runtime.review_verifier.rebuild_review(
            verdict=verdict,
            evidence_pack=pack,
            current_closure=roots.closure,
            parse_history=roots.parse_history,
            review_version=1,
        )
        head = runtime.evidence.get_audit_head(RUN_ID)
        before = _row_counts(runtime.database, *tracked)
        _damage_raw_response(runtime.workspace_root, roots.response, damage)

        with pytest.raises(ModelResponseStoreError) as rejected:
            roots.repository.commit_verdict_review(
                RUN_ID,
                screening_commit.case.revision,
                head,
                roots.closure,
                verdict,
                review,
            )

    assert rejected.value.reason_code == expected_failure
    assert _row_counts(runtime.database, *tracked) == before
    assert runtime.evidence.load_case(RUN_ID, runtime.case_id) == screening_commit.case
    assert runtime.evidence.get_audit_head(RUN_ID) == head
