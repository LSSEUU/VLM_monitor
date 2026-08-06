"""Offline service-level M3 flows over real SQLite and SecureWorkspace adapters."""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from labcourt.adapters.pillow_media import encode_rgb_png
from labcourt.adapters.storage.model_response_store import SecureModelResponseStore
from labcourt.adapters.storage.readonly_m3_artifacts import ReadonlyM3ArtifactRepository
from labcourt.adapters.storage.readonly_sqlite import (
    readonly_sqlite_snapshot,
    snapshot_run_counts,
)
from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.adapters.storage.sqlite_m3_repository import SQLiteM3Repository
from labcourt.adapters.storage.sqlite_repository import (
    MigrationRunner,
    SQLiteEvidenceRepository,
)
from labcourt.adapters.stored_png_verifier import StoredPngVerifier
from labcourt.application.procedural_review import DeterministicProceduralReviewVerifier
from labcourt.application.screening_request import (
    prepare_screening_request,
)
from labcourt.config_loader import load_config
from labcourt.contracts.backlog import (
    BacklogLeaseIdentity,
    BacklogRetryContext,
    BacklogRetryDisposition,
)
from labcourt.contracts.canonical import canonical_bytes
from labcourt.contracts.config import AppConfig
from labcourt.contracts.detections import Detection
from labcourt.contracts.enums import (
    ArtifactKind,
    BacklogReasonCode,
    BacklogStage,
    CaseStatus,
    CropSource,
    MediaAccess,
    MediaAvailability,
    MediaType,
    PrivacyPolicy,
    PrivacyReasonCode,
)
from labcourt.contracts.events import CandidateEvent, derive_case_id
from labcourt.contracts.evidence import (
    Crop,
    EvidencePack,
    EvidencePackDraft,
    PrivacyReceipt,
    TrackSummary,
)
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.m3_operations import (
    FakeVLMFailureFixtureInput,
    FakeVLMFixtureBundle,
    FakeVLMFixtureDisposition,
    FakeVLMResponseFixtureInput,
    M3ProcessDisposition,
)
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.storage import ArtifactRef
from labcourt.ports.pixels import rgb8_pixel_sha256
from labcourt.ports.screening_repository import ModelCallClaimStatus
from labcourt.services.m3 import build_screening_prompt_catalog
from labcourt.services.m3_operations import (
    M3OperationsBoundaryCode,
    M3OperationsBoundaryError,
    open_m3_operations_service,
)

ROOT = Path(__file__).parents[2]
FIXTURES = ROOT / "tests" / "fixtures" / "m2"
RUN_ID = "run-01"
RECORDED_AT = datetime(2026, 7, 28, 12, 0, tzinfo=UTC)


@dataclass(frozen=True, slots=True)
class _Runtime:
    config: AppConfig
    manifest: RunManifest
    workspace_root: Path
    database: Path
    pack: EvidencePack
    case_id: str
    initial_cache_key: str
    raw_response: bytes


@dataclass(frozen=True, slots=True)
class _ReadyFixture:
    case_id: str
    cache_key: str
    raw_response: bytes


def _clock() -> datetime:
    return RECORDED_AT


def _config() -> AppConfig:
    return load_config(ROOT / "configs" / "demo.yaml")


def _manifest() -> RunManifest:
    return RunManifest.model_validate_json(
        (FIXTURES / "run-manifest-fake.json").read_text(encoding="utf-8")
    )


def _event(*, start_frame: int = 0) -> CandidateEvent:
    base = CandidateEvent.model_validate_json(
        (FIXTURES / "candidate-event-presence.json").read_text(encoding="utf-8")
    )
    if start_frame == 0:
        return base
    payload = base.model_dump(mode="python", exclude_computed_fields=True)
    payload["start_frame"] = start_frame
    objective_facts = list(payload["objective_facts"])
    duration = dict(objective_facts[0])
    duration["value"] = base.end_frame_exclusive - start_frame
    objective_facts[0] = duration
    payload["objective_facts"] = objective_facts
    return CandidateEvent.model_validate(payload)


def _event_for_track(index: int) -> CandidateEvent:
    payload = _event().model_dump(mode="python", exclude_computed_fields=True)
    payload["primary_track_ref"] = f"cam-01:epoch-01:bounded-{index:04d}"
    return CandidateEvent.model_validate(payload)


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


def _detection(manifest: RunManifest) -> Detection:
    return Detection(
        detection_id="det-bottle-090",
        frame_id=_frame().frame_id,
        label="reagent_bottle",
        bbox=BBoxXYXY(x1=10, y1=20, x2=110, y2=220),
        score=0.92,
        track_ref=_event().primary_track_ref,
        model_manifest_id=manifest.models["detector"].model_manifest_id,
    )


def _draft(event: CandidateEvent, png: bytes, pixel_sha256: str) -> EvidencePackDraft:
    frame = _frame()
    media_sha256 = hashlib.sha256(png).hexdigest()
    source_refs = tuple(
        sorted(
            (
                ArtifactRef(kind=ArtifactKind.FRAME, artifact_id=frame.frame_id),
                ArtifactRef(
                    kind=ArtifactKind.DETECTION,
                    artifact_id="det-bottle-090",
                ),
            ),
            key=lambda ref: ref.sort_key,
        )
    )
    crop = Crop(
        frame_id=frame.frame_id,
        source=CropSource.DETECTION_FOCUS,
        bbox=BBoxXYXY(x1=10, y1=20, x2=110, y2=220),
        source_refs=source_refs,
        local_path=f"{RUN_ID}/frames/{media_sha256}.png",
        availability=MediaAvailability.AVAILABLE,
        source_media_sha256=frame.content_sha256,
        pixel_sha256=pixel_sha256,
        media_sha256=media_sha256,
        output_width=100,
        output_height=200,
        size_bytes=len(png),
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


def _valid_model_response(crop_id: str) -> bytes:
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
            "prosecution_summary": "Synthetic fixture citation supports the test result.",
            "rationale_summary": "Only structured fixture fields are evaluated.",
            "violation_probability": 0.95,
            "violation_type": "REAGENT_CONTAINER_OPEN",
        }
    )


def _setup_ready_runtime(
    tmp_path: Path,
    *,
    run_manifest: RunManifest | None = None,
) -> _Runtime:
    config = _config()
    manifest = run_manifest or _manifest()
    workspace_root = tmp_path / "workspace"
    workspace_root.mkdir(parents=True)
    database = workspace_root / config.storage.database_filename
    MigrationRunner(database, config.storage.busy_timeout_ms, clock=_clock).apply_all()

    width, height = 100, 200
    pixels = bytes(width * height * 3)
    png = encode_rgb_png(width, height, pixels)
    pixel_sha256 = rgb8_pixel_sha256(width, height, pixels)
    event = _event()
    if event.manifest_id != manifest.manifest_id:
        event = event.model_copy(update={"manifest_id": manifest.manifest_id})
    draft = _draft(event, png, pixel_sha256)
    crop = draft.focus_crops[0]

    with SecureWorkspace(workspace_root, config.storage.max_media_bytes) as workspace:
        workspace.ensure_private_directory(RUN_ID)
        workspace.ensure_private_directory(f"{RUN_ID}/frames")
        workspace.create_new(crop.local_path, png, crop.media_sha256)
        verifier = StoredPngVerifier(
            run_id=RUN_ID,
            workspace=workspace,
            max_media_bytes=config.storage.max_media_bytes,
            max_image_pixels=config.storage.max_image_pixels,
        )
        evidence = SQLiteEvidenceRepository(
            database,
            config.storage.busy_timeout_ms,
            verifier=verifier,
            clock=_clock,
        )
        evidence.register_run(RUN_ID, manifest)
        evidence.register_frame(RUN_ID, _frame())
        evidence.register_detection(RUN_ID, _detection(manifest))
        evidence.create_or_get_case(RUN_ID, event)
        published = evidence.publish_pack(RUN_ID, 1, draft)

    raw_response = _valid_model_response(published.pack.focus_crops[0].crop_id)
    prepared = prepare_screening_request(
        published.pack,
        config,
        manifest,
        build_screening_prompt_catalog(manifest),
    )
    return _Runtime(
        config=config,
        manifest=manifest,
        workspace_root=workspace_root,
        database=database,
        pack=published.pack,
        case_id=published.pack.case_id,
        initial_cache_key=prepared.request.cache_key,
        raw_response=raw_response,
    )


def _publish_ready_events(
    runtime: _Runtime,
    events: tuple[CandidateEvent, ...],
) -> tuple[_ReadyFixture, ...]:
    width, height = 100, 200
    pixels = bytes(width * height * 3)
    png = encode_rgb_png(width, height, pixels)
    pixel_sha256 = rgb8_pixel_sha256(width, height, pixels)
    ready: list[_ReadyFixture] = []

    with SecureWorkspace(
        runtime.workspace_root,
        runtime.config.storage.max_media_bytes,
    ) as workspace:
        verifier = StoredPngVerifier(
            run_id=RUN_ID,
            workspace=workspace,
            max_media_bytes=runtime.config.storage.max_media_bytes,
            max_image_pixels=runtime.config.storage.max_image_pixels,
        )
        evidence = SQLiteEvidenceRepository(
            runtime.database,
            runtime.config.storage.busy_timeout_ms,
            verifier=verifier,
            clock=_clock,
        )
        for event in events:
            created = evidence.create_or_get_case(RUN_ID, event)
            published = evidence.publish_pack(
                RUN_ID,
                created.revision,
                _draft(event, png, pixel_sha256),
            )
            raw_response = _valid_model_response(published.pack.focus_crops[0].crop_id)
            prepared = prepare_screening_request(
                published.pack,
                runtime.config,
                runtime.manifest,
                build_screening_prompt_catalog(runtime.manifest),
            )
            ready.append(
                _ReadyFixture(
                    case_id=published.pack.case_id,
                    cache_key=prepared.request.cache_key,
                    raw_response=raw_response,
                )
            )
    return tuple(ready)


def _empty_bundle() -> FakeVLMFixtureBundle:
    return FakeVLMFixtureBundle(
        schema_version="m3-fake-vlm-fixture-bundle-v1",
        fixtures=(),
    )


def _response_bundle(cache_key: str, raw_response: bytes) -> FakeVLMFixtureBundle:
    return _response_bundle_many(((cache_key, raw_response),))


def _response_bundle_many(
    entries: tuple[tuple[str, bytes], ...],
) -> FakeVLMFixtureBundle:
    fixtures = tuple(
        sorted(
            (
                FakeVLMResponseFixtureInput(
                    disposition=FakeVLMFixtureDisposition.RESPONSE,
                    cache_key=cache_key,
                    raw_response_utf8=raw_response.decode("utf-8"),
                    input_tokens=23,
                    output_tokens=11,
                    latency_ms=17,
                )
                for cache_key, raw_response in entries
            ),
            key=lambda fixture: fixture.cache_key,
        )
    )
    return FakeVLMFixtureBundle(
        schema_version="m3-fake-vlm-fixture-bundle-v1",
        fixtures=fixtures,
    )


def _outage_bundle(cache_key: str) -> FakeVLMFixtureBundle:
    return FakeVLMFixtureBundle(
        schema_version="m3-fake-vlm-fixture-bundle-v1",
        fixtures=(
            FakeVLMFailureFixtureInput(
                disposition=FakeVLMFixtureDisposition.OUTAGE,
                cache_key=cache_key,
            ),
        ),
    )


def test_process_success_and_idempotent_rerun_use_one_real_authority(
    tmp_path: Path,
) -> None:
    runtime = _setup_ready_runtime(tmp_path)
    with open_m3_operations_service(
        config=runtime.config,
        run_id=RUN_ID,
        workspace_root=runtime.workspace_root,
        database_path=runtime.database,
        fixture_bundle=_response_bundle(runtime.initial_cache_key, runtime.raw_response),
        clock=_clock,
    ) as service:
        first = service.process_run(case_id=runtime.case_id, max_cases=1)
        second = service.process_run(case_id=runtime.case_id, max_cases=1)

    assert first.perception_mode == "SIMULATED PERCEPTION"
    assert first.model_mode == "FAKE VLM"
    assert first.outcomes[0].disposition == M3ProcessDisposition.PROCESSED
    assert first.outcomes[0].status == CaseStatus.READY_FOR_ALERT_POLICY
    assert first.outcomes[0].screening_result_ref is not None
    assert first.outcomes[0].verdict_ref is not None
    assert first.outcomes[0].procedural_review_ref is not None
    assert first.counts.pipeline_invocations == 1
    assert second.outcomes[0].disposition == M3ProcessDisposition.OBSERVED_EXISTING
    assert second.outcomes[0].status == CaseStatus.READY_FOR_ALERT_POLICY
    assert second.counts.pipeline_invocations == 0
    assert second.outcomes[0].revision == first.outcomes[0].revision


@pytest.mark.parametrize("fixture_mode", ["OUTAGE", "MISSING"])
def test_provider_failure_is_a_successful_controlled_backlog_flow(
    tmp_path: Path,
    fixture_mode: str,
) -> None:
    runtime = _setup_ready_runtime(tmp_path / fixture_mode.lower())
    bundle = (
        _outage_bundle(runtime.initial_cache_key) if fixture_mode == "OUTAGE" else _empty_bundle()
    )
    with open_m3_operations_service(
        config=runtime.config,
        run_id=RUN_ID,
        workspace_root=runtime.workspace_root,
        database_path=runtime.database,
        fixture_bundle=bundle,
        clock=_clock,
    ) as service:
        report = service.process_run(case_id=runtime.case_id, max_cases=1)

    outcome = report.outcomes[0]
    assert outcome.disposition == M3ProcessDisposition.DEFERRED_TO_BACKLOG
    assert outcome.status == CaseStatus.BACKLOGGED
    assert outcome.backlog_item_ref is not None
    item = SQLiteM3Repository(
        runtime.database,
        runtime.config.storage.busy_timeout_ms,
        clock=_clock,
    ).load_backlog_item(RUN_ID, outcome.backlog_item_ref.artifact_id)
    assert item.reason_code == BacklogReasonCode.PROVIDER_UNAVAILABLE


def test_process_run_prioritizes_ready_case_in_large_bounded_selection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = _setup_ready_runtime(tmp_path)
    evidence = SQLiteEvidenceRepository(
        runtime.database,
        runtime.config.storage.busy_timeout_ms,
        clock=_clock,
    )
    candidate_case_ids: list[str] = []
    for index in range(1, 1_001):
        event = _event_for_track(index)
        candidate_case_ids.append(derive_case_id(event.event_id))
        evidence.create_or_get_case(RUN_ID, event)

    assert min(candidate_case_ids) < runtime.case_id

    def fail_unbounded_list(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("process_run must not materialize the unbounded event inventory")

    monkeypatch.setattr(SQLiteEvidenceRepository, "list_events", fail_unbounded_list)

    with open_m3_operations_service(
        config=runtime.config,
        run_id=RUN_ID,
        workspace_root=runtime.workspace_root,
        database_path=runtime.database,
        fixture_bundle=_response_bundle(runtime.initial_cache_key, runtime.raw_response),
        clock=_clock,
    ) as service:
        report = service.process_run(max_cases=1)

    assert report.available_case_count == 1_001
    assert report.selection_truncated
    assert report.counts.selected_cases == 1
    assert report.counts.pipeline_invocations == 1
    assert report.outcomes[0].case_id == runtime.case_id
    assert report.outcomes[0].initial_status == CaseStatus.EVIDENCE_READY
    assert report.outcomes[0].status == CaseStatus.READY_FOR_ALERT_POLICY
    assert report.outcomes[0].disposition == M3ProcessDisposition.PROCESSED


def test_repeated_bounded_process_run_advances_all_actionable_cases(
    tmp_path: Path,
) -> None:
    runtime = _setup_ready_runtime(tmp_path)
    added = _publish_ready_events(
        runtime,
        (_event_for_track(1_001), _event_for_track(1_002)),
    )
    actionable = (
        _ReadyFixture(
            case_id=runtime.case_id,
            cache_key=runtime.initial_cache_key,
            raw_response=runtime.raw_response,
        ),
        *added,
    )
    expected_case_ids = tuple(sorted(item.case_id for item in actionable))

    evidence = SQLiteEvidenceRepository(
        runtime.database,
        runtime.config.storage.busy_timeout_ms,
        clock=_clock,
    )
    candidate_event = _event_for_track(721)
    candidate_case_id = derive_case_id(candidate_event.event_id)
    assert candidate_case_id < expected_case_ids[0]
    evidence.create_or_get_case(RUN_ID, candidate_event)

    fixture_bundle = _response_bundle_many(
        tuple((item.cache_key, item.raw_response) for item in actionable)
    )
    with open_m3_operations_service(
        config=runtime.config,
        run_id=RUN_ID,
        workspace_root=runtime.workspace_root,
        database_path=runtime.database,
        fixture_bundle=fixture_bundle,
        clock=_clock,
    ) as service:
        reports = tuple(service.process_run(max_cases=1) for _ in actionable)
        drained = service.process_run(max_cases=1)

    assert tuple(report.outcomes[0].case_id for report in reports) == expected_case_ids
    assert all(report.available_case_count == 4 for report in reports)
    assert all(report.selection_truncated for report in reports)
    assert all(report.counts.pipeline_invocations == 1 for report in reports)
    assert all(report.outcomes[0].status == CaseStatus.READY_FOR_ALERT_POLICY for report in reports)
    assert drained.outcomes[0].case_id == candidate_case_id
    assert drained.outcomes[0].disposition == M3ProcessDisposition.SKIPPED_NOT_READY
    assert drained.counts.pipeline_invocations == 0


def test_backlog_retry_reuses_exact_cached_response_with_empty_fixture_bundle(
    tmp_path: Path,
) -> None:
    runtime = _setup_ready_runtime(tmp_path)
    with open_m3_operations_service(
        config=runtime.config,
        run_id=RUN_ID,
        workspace_root=runtime.workspace_root,
        database_path=runtime.database,
        fixture_bundle=_outage_bundle(runtime.initial_cache_key),
        clock=_clock,
    ) as service:
        backlogged = service.process_run(case_id=runtime.case_id, max_cases=1)

    backlog_ref = backlogged.outcomes[0].backlog_item_ref
    assert backlog_ref is not None
    pending = SQLiteM3Repository(
        runtime.database,
        runtime.config.storage.busy_timeout_ms,
        clock=_clock,
    ).load_backlog_item(RUN_ID, backlog_ref.artifact_id)
    retry_context = BacklogRetryContext(
        backlog_item_id=pending.item_id,
        retry_generation=pending.retry_generation,
    )
    retry_request = prepare_screening_request(
        runtime.pack,
        runtime.config,
        runtime.manifest,
        build_screening_prompt_catalog(runtime.manifest),
        backlog_retry_context=retry_context,
    ).request
    assert retry_request.cache_key == runtime.initial_cache_key
    with sqlite3.connect(runtime.database) as connection:
        claim_row = connection.execute(
            """
            SELECT request_id, request_sha256, cache_key, takeover_count
            FROM model_call_claims
            """
        ).fetchone()
        authority_row = connection.execute(
            """
            SELECT request_id, request_sha256, cache_key, failure_code,
                   delivery_certainty, backlog_item_id, retry_generation
            FROM model_call_failure_authorities
            """
        ).fetchone()
    assert claim_row is not None
    assert authority_row == (
        claim_row[0],
        claim_row[1],
        claim_row[2],
        "PROVIDER_OUTAGE",
        "DEFINITELY_NOT_SENT",
        pending.item_id,
        0,
    )
    assert retry_request.request_id == claim_row[0]
    assert retry_request.request_sha256 == claim_row[1]

    with SecureWorkspace(
        runtime.workspace_root,
        runtime.config.storage.max_media_bytes,
    ) as workspace:
        verifier = StoredPngVerifier(
            run_id=RUN_ID,
            workspace=workspace,
            max_media_bytes=runtime.config.storage.max_media_bytes,
            max_image_pixels=runtime.config.storage.max_image_pixels,
        )
        evidence = SQLiteEvidenceRepository(
            runtime.database,
            runtime.config.storage.busy_timeout_ms,
            verifier=verifier,
            clock=_clock,
        )
        response_store = SecureModelResponseStore(workspace)
        review = DeterministicProceduralReviewVerifier(runtime.config, evidence)
        repository = SQLiteM3Repository(
            runtime.database,
            runtime.config.storage.busy_timeout_ms,
            clock=lambda: RECORDED_AT - timedelta(minutes=10),
            current_pack_verifier=evidence.verify_current_pack,
            raw_response_verifier=response_store,
            procedural_review_verifier=review,
            semantic_verifier=review,
        )
        leased = repository.lease_next(
            RUN_ID,
            BacklogStage.SCREENING,
            "9" * 64,
            RECORDED_AT - timedelta(minutes=9),
        )
        assert leased is not None
        lease_identity = BacklogLeaseIdentity(
            run_id=leased.run_id,
            item_id=leased.item_id,
            lease_id=leased.lease_id or "",
            attempt_count=leased.attempt_count,
            retry_generation=leased.retry_generation,
        )
        owner = "cached-retry-owner-token-0000000001"
        claim = repository.claim_model_call(
            RUN_ID,
            retry_request,
            owner,
            lease_identity,
        )
        assert claim.status == ModelCallClaimStatus.ACQUIRED
        response = response_store.publish(
            retry_request,
            runtime.raw_response,
            input_tokens=23,
            output_tokens=11,
            latency_ms=17,
        )
        repository.complete_model_call(RUN_ID, retry_request, response, owner)
        response_store.acknowledge(retry_request, response)
        with sqlite3.connect(runtime.database) as connection:
            assert connection.execute(
                "SELECT status, takeover_count FROM model_call_claims"
            ).fetchone() == ("COMPLETED", 1)
            assert connection.execute(
                "SELECT COUNT(*) FROM model_call_failure_authorities"
            ).fetchone() == (1,)

    with open_m3_operations_service(
        config=runtime.config,
        run_id=RUN_ID,
        workspace_root=runtime.workspace_root,
        database_path=runtime.database,
        fixture_bundle=_empty_bundle(),
        clock=_clock,
    ) as service:
        lease_floor = service.minimum_backlog_lease_seconds
        assert lease_floor > 0
        with pytest.raises(ValueError, match="cannot cover"):
            service.build_backlog_retry_coordinator(lease_duration_seconds=lease_floor - 1)
        retried = service.backlog_retry_run_once(worker_id="worker-01")

    assert retried.disposition == BacklogRetryDisposition.COMPLETED
    assert retried.item is not None
    assert retried.item.status.value == "COMPLETED"
    with readonly_sqlite_snapshot(runtime.database) as snapshot_database:
        counts = snapshot_run_counts(snapshot_database, RUN_ID)
        authority = ReadonlyM3ArtifactRepository(snapshot_database).scan(RUN_ID)
    assert counts.model_call_failure_authorities == 1
    assert authority.failures == ()


def test_composition_rejects_non_fake_profile_and_database_outside_workspace(
    tmp_path: Path,
) -> None:
    config = _config()
    workspace_root = tmp_path / "workspace"
    workspace_root.mkdir()
    expected_database = workspace_root / config.storage.database_filename

    with (
        pytest.raises(ValueError, match="exactly match"),
        open_m3_operations_service(
            config=config,
            run_id=RUN_ID,
            workspace_root=workspace_root,
            database_path=tmp_path / config.storage.database_filename,
            fixture_bundle=_empty_bundle(),
            clock=_clock,
        ),
    ):
        raise AssertionError("invalid database scope must not open")

    with (
        pytest.raises(ValueError, match="parent traversal"),
        open_m3_operations_service(
            config=config,
            run_id=RUN_ID,
            workspace_root=workspace_root,
            database_path=(workspace_root / "nested" / ".." / config.storage.database_filename),
            fixture_bundle=_empty_bundle(),
            clock=_clock,
        ),
    ):
        raise AssertionError("parent traversal must not open")

    with (
        pytest.raises(ValueError, match="parent traversal"),
        open_m3_operations_service(
            config=config,
            run_id=RUN_ID,
            workspace_root=tmp_path / "alias" / ".." / "workspace",
            database_path=expected_database,
            fixture_bundle=_empty_bundle(),
            clock=_clock,
        ),
    ):
        raise AssertionError("workspace traversal must not open")

    payload = config.model_dump(mode="python", exclude_computed_fields=True)
    providers = {name: dict(profile) for name, profile in payload["providers"].items()}
    screening_profile = dict(providers[config.screening.provider_profile])
    screening_profile["provider"] = "unsupported-local-provider"
    providers[config.screening.provider_profile] = screening_profile
    payload["providers"] = providers
    non_fake = AppConfig.model_validate(payload)

    with (
        pytest.raises(M3OperationsBoundaryError) as caught,
        open_m3_operations_service(
            config=non_fake,
            run_id=RUN_ID,
            workspace_root=workspace_root,
            database_path=expected_database,
            fixture_bundle=_empty_bundle(),
            clock=_clock,
        ),
    ):
        raise AssertionError("unsupported deployment must not open")
    assert caught.value.code == M3OperationsBoundaryCode.DEPLOYMENT_UNSUPPORTED
