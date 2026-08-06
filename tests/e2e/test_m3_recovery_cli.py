from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner, Result

from labcourt.adapters.storage.model_response_store import SecureModelResponseStore
from labcourt.adapters.storage.secure_workspace import SecureWorkspace
from labcourt.adapters.storage.sqlite_m3_repository import SQLiteM3Repository
from labcourt.adapters.storage.sqlite_repository import MigrationRunner, SQLiteEvidenceRepository
from labcourt.cli import app
from labcourt.config_loader import load_config
from labcourt.contracts.detections import Detection
from labcourt.contracts.enums import (
    ArtifactKind,
    CropSource,
    EvidenceClass,
    ExecutionLocation,
    MediaAccess,
    MediaAvailability,
    MediaType,
    PrivacyPolicy,
    PrivacyReasonCode,
    VerificationStatus,
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
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.geometry import BBoxXYXY
from labcourt.contracts.m3_models import PromptManifest, VlmCallBudget
from labcourt.contracts.manifests import RunManifest
from labcourt.contracts.model_response_recovery import (
    ModelResponseArtifactPhase,
    ModelResponseRecoveryArea,
    ModelResponseRecoveryDisposition,
    ModelResponseRecoveryReason,
)
from labcourt.contracts.screening import VLMMediaRef, VLMRequest
from labcourt.contracts.storage import ArtifactRef, ArtifactVerification

PROJECT_ROOT = Path(__file__).parents[2]
CONFIG_PATH = PROJECT_ROOT / "configs" / "demo.yaml"
FIXTURES = PROJECT_ROOT / "tests" / "fixtures" / "m2"
RUNNER = CliRunner()


class _VerifiedCropStore:
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


def _draft(run_id: str, manifest: RunManifest) -> EvidencePackDraft:
    event = _event()
    frame = _frame()
    frame_ref = ArtifactRef(kind=ArtifactKind.FRAME, artifact_id=frame.frame_id)
    detection_ref = ArtifactRef(kind=ArtifactKind.DETECTION, artifact_id="det-bottle-090")
    source_refs = tuple(sorted((detection_ref, frame_ref), key=lambda ref: ref.sort_key))
    crop = Crop(
        frame_id=frame.frame_id,
        source=CropSource.DETECTION_FOCUS,
        bbox=BBoxXYXY(x1=10, y1=20, x2=110, y2=220),
        source_refs=source_refs,
        local_path="frames/focus.png",
        availability=MediaAvailability.AVAILABLE,
        source_media_sha256="a" * 64,
        pixel_sha256="b" * 64,
        media_sha256="c" * 64,
        output_width=100,
        output_height=200,
        size_bytes=512,
        media_type=MediaType.IMAGE_PNG,
        encoding_version="png-v1",
        privacy_receipt=PrivacyReceipt(
            policy=PrivacyPolicy.FULL_REDACTION,
            transform_version=manifest.privacy_transform_version,
            media_access=MediaAccess.LOCAL_ONLY,
            reason_code=PrivacyReasonCode.POLICY_LOCAL_ONLY,
            input_refs=source_refs,
            fill_rgb=(0, 0, 0),
        ),
        primary_track_ref=event.primary_track_ref,
    )
    return EvidencePackDraft(
        run_id=run_id,
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


def _setup_scope(tmp_path: Path, run_id: str) -> tuple[Path, Path, int, EvidencePack]:
    config = load_config(CONFIG_PATH)
    workspace_root = tmp_path / "runs"
    workspace_root.mkdir()
    database = workspace_root / config.storage.database_filename
    MigrationRunner(database, config.storage.busy_timeout_ms).apply_all()
    repository = SQLiteEvidenceRepository(
        database,
        config.storage.busy_timeout_ms,
        verifier=_VerifiedCropStore(),
    )
    manifest = _manifest()
    event = _event()
    frame = _frame()
    repository.register_run(run_id, manifest)
    repository.register_frame(run_id, frame)
    repository.register_detection(
        run_id,
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
    repository.create_or_get_case(run_id, event)
    published = repository.publish_pack(run_id, 1, _draft(run_id, manifest))
    return workspace_root, database, config.storage.busy_timeout_ms, published.pack


def _request(run_id: str, pack: EvidencePack) -> VLMRequest:
    manifest = _manifest()
    model = manifest.models["screening"]
    crop = pack.focus_crops[0]
    media = VLMMediaRef(
        crop_id=crop.crop_id,
        media_sha256=crop.media_sha256,
        local_path=f"{run_id}/frames/{crop.media_sha256}.png",
        source=crop.source,
        media_access=crop.privacy_receipt.media_access,
        privacy_policy=crop.privacy_receipt.policy,
        privacy_transform_version=crop.privacy_receipt.transform_version,
        width=crop.output_width,
        height=crop.output_height,
    )
    return VLMRequest(
        run_id=run_id,
        case_id=pack.case_id,
        evidence_pack_id=pack.pack_id,
        evidence_pack_version=pack.version,
        provider_profile="fake-screening",
        provider=model.provider,
        model=model.model,
        revision=model.revision,
        model_manifest_id=model.model_manifest_id,
        execution_location=ExecutionLocation.LOCAL,
        prompt_manifest=PromptManifest(
            prompt_id="screening-v1",
            role=VlmRole.SCREENING,
            template_sha256="1" * 64,
            output_schema_sha256="2" * 64,
            prompt_bundle_sha256=manifest.prompt_bundle_sha256,
            renderer_version="jinja-3-1",
        ),
        rendered_prompt_sha256="3" * 64,
        violation_type=pack.event.violation_type,
        evidence_class=EvidenceClass.PRESENCE,
        rule_summary="Apply the configured laboratory rule.",
        media=(media,),
        allowed_evidence_refs=(ArtifactRef(kind=ArtifactKind.CROP, artifact_id=crop.crop_id),),
        objective_summary={"duration_frames": 91},
        temperature=0.0,
        seed=7,
        budget=VlmCallBudget(
            max_images=1,
            max_input_pixels=100_000,
            max_output_tokens=1_024,
            pricing_currency="USD",
            input_cost_per_million_tokens=0.0,
            output_cost_per_million_tokens=0.0,
            max_estimated_cost=0.0,
            max_response_bytes=65_536,
            max_json_depth=8,
            max_json_fields=128,
            max_string_chars=8_192,
            timeout_seconds=3_600.0,
            claim_completion_grace_seconds=300.0,
        ),
        manifest_id=pack.manifest_id,
    )


def _invoke(run_id: str) -> Result:
    return RUNNER.invoke(
        app,
        [
            "maintenance",
            "recover",
            "--run-id",
            run_id,
            "--config",
            str(CONFIG_PATH),
            "--json",
            "--max-items",
            "10",
            "--minimum-age-minutes",
            "60",
        ],
    )


def test_recovery_cli_defers_an_unexpired_active_claim_without_artifact_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id = "m3-recovery-active"
    _, database, busy_timeout_ms, pack = _setup_scope(tmp_path, run_id)
    request = _request(run_id, pack)
    repository = SQLiteM3Repository(database, busy_timeout_ms)
    repository.claim_model_call(run_id, request, "active-owner-" + "a" * 51)
    monkeypatch.chdir(tmp_path)

    result = _invoke(run_id)

    assert result.exit_code == 0, result.output
    model = json.loads(result.stdout)["model_response_report"]
    assert model["artifact_phase"] == ModelResponseArtifactPhase.DEFERRED_ACTIVE_CLAIM.value
    assert model["artifacts_scanned"] == 0
    assert model["artifact_scan_complete"] is False
    assert model["passed"] is True
    assert len(model["items"]) == 1
    item = model["items"][0]
    assert item["area"] == ModelResponseRecoveryArea.MODEL_CALL.value
    assert item["disposition"] == ModelResponseRecoveryDisposition.DEFERRED.value
    assert item["reason_code"] == ModelResponseRecoveryReason.ACTIVE_LEASE_UNEXPIRED.value


def test_recovery_cli_expired_claim_without_journal_requires_attention(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id = "m3-recovery-expired-no-journal"
    _, database, busy_timeout_ms, pack = _setup_scope(tmp_path, run_id)
    request = _request(run_id, pack)

    def old_clock() -> datetime:
        return datetime(2020, 1, 1, tzinfo=UTC)

    repository = SQLiteM3Repository(database, busy_timeout_ms, clock=old_clock)
    repository.claim_model_call(run_id, request, "expired-owner-" + "e" * 50)
    monkeypatch.chdir(tmp_path)

    result = _invoke(run_id)

    assert result.exit_code == 1, result.output
    payload = json.loads(result.stdout)
    assert payload["passed"] is False
    assert payload["requires_attention"] is True
    model = payload["model_response_report"]
    assert model["artifact_phase"] == ModelResponseArtifactPhase.DEFERRED_ACTIVE_CLAIM.value
    assert model["artifact_scan_complete"] is False
    assert model["artifacts_scanned"] == 0
    assert model["artifact_bytes_scanned"] == 0
    assert model["items"][0]["reason_code"] == (
        ModelResponseRecoveryReason.ACTIVE_EXPIRED_NO_JOURNAL.value
    )


def test_recovery_cli_cleans_a_completed_claim_journal_and_verifies_its_exact_response(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id = "m3-recovery-terminal"
    workspace_root, database, busy_timeout_ms, pack = _setup_scope(tmp_path, run_id)
    request = _request(run_id, pack)
    owner_token = "terminal-owner-" + "b" * 49
    config = load_config(CONFIG_PATH)
    with SecureWorkspace(
        workspace_root,
        max_file_bytes=config.storage.max_media_bytes,
    ) as workspace:
        response_store = SecureModelResponseStore(workspace)
        repository = SQLiteM3Repository(
            database,
            busy_timeout_ms,
            raw_response_verifier=response_store,
        )
        repository.claim_model_call(run_id, request, owner_token)
        response = response_store.publish(request, b'{"result":"durable"}')
        repository.complete_model_call(run_id, request, response, owner_token)

    journal = (
        workspace_root
        / ".staging"
        / run_id
        / f"model-request-{request.request_id}"
        / "receipt.json"
    )
    final_response = workspace_root / run_id / "model_responses" / f"{response.response_id}.json"
    assert journal.is_file()
    monkeypatch.chdir(tmp_path)

    result = _invoke(run_id)

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["passed"] is True
    model = payload["model_response_report"]
    assert model["artifact_phase"] == ModelResponseArtifactPhase.COMPLETED.value
    assert model["claim_limit"] == 10_000
    assert model["artifact_limit"] == 10
    assert model["claim_scan_complete"] is True
    assert model["artifact_scan_complete"] is True
    assert model["artifact_file_bytes_limit"] == config.screening.max_response_bytes
    assert model["artifact_total_bytes_limit"] == (10 * config.screening.max_response_bytes)
    assert model["artifact_bytes_scanned"] == len(b'{"result":"durable"}')
    claim_item = next(
        item for item in model["items"] if item["area"] == ModelResponseRecoveryArea.MODEL_CALL
    )
    # Startup recovery performs a provider-free preflight and then a fenced
    # rescan. The preflight removes the durable journal; the public report is
    # the fenced terminal observation after that mutation.
    assert claim_item["disposition"] == ModelResponseRecoveryDisposition.VERIFIED.value
    assert claim_item["reason_code"] == ModelResponseRecoveryReason.JOURNAL_ALREADY_ABSENT.value
    response_item = next(
        item for item in model["items"] if item["area"] == ModelResponseRecoveryArea.FINAL_RESPONSE
    )
    assert response_item["disposition"] == ModelResponseRecoveryDisposition.RETAINED.value
    assert (
        response_item["reason_code"]
        == ModelResponseRecoveryReason.DATABASE_REFERENCED_ARTIFACT.value
    )
    assert response_item["content_sha256"] == response.content_sha256
    assert not journal.exists()
    assert final_response.read_bytes() == b'{"result":"durable"}'


def test_recovery_cli_returns_exit_one_for_a_typed_model_response_anomaly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id = "m3-recovery-anomaly"
    workspace_root, _, _, _ = _setup_scope(tmp_path, run_id)
    config = load_config(CONFIG_PATH)
    data = b"unknown-model-response-entry"
    relative_path = f"{run_id}/model_responses/notes.txt"
    with SecureWorkspace(
        workspace_root,
        max_file_bytes=config.storage.max_media_bytes,
    ) as workspace:
        for directory in (run_id, f"{run_id}/model_responses"):
            workspace.ensure_private_directory(directory)
        workspace.create_new(relative_path, data, hashlib.sha256(data).hexdigest())
    source = workspace_root / run_id / "model_responses" / "notes.txt"
    monkeypatch.chdir(tmp_path)

    result = _invoke(run_id)

    assert result.exit_code == 1, result.output
    payload = json.loads(result.stdout)
    assert payload["passed"] is False
    assert payload["requires_attention"] is True
    model = payload["model_response_report"]
    assert model["artifact_phase"] == (
        ModelResponseArtifactPhase.SUPPRESSED_INTEGRITY_FAILURE.value
    )
    assert len(model["items"]) == 1
    item = model["items"][0]
    assert item["area"] == ModelResponseRecoveryArea.FINAL_RESPONSE.value
    assert item["disposition"] == ModelResponseRecoveryDisposition.ANOMALY.value
    assert item["reason_code"] == ModelResponseRecoveryReason.UNKNOWN_ENTRY_SHAPE.value
    assert source.read_bytes() == data
    assert not (workspace_root / ".quarantine").exists()


def test_recovery_cli_human_summary_includes_the_m3_phase(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id = "m3-recovery-human-summary"
    _setup_scope(tmp_path, run_id)
    monkeypatch.chdir(tmp_path)

    result = RUNNER.invoke(
        app,
        [
            "maintenance",
            "recover",
            "--run-id",
            run_id,
            "--config",
            str(CONFIG_PATH),
            "--max-items",
            "10",
            "--minimum-age-minutes",
            "60",
        ],
    )

    assert result.exit_code == 0, result.output
    assert f"recovered run={run_id}" in result.stdout
    assert "model_response_phase=COMPLETED" in result.stdout
    assert "model_response_items=0" in result.stdout
    assert "model_response_anomalies=0" in result.stdout


def test_recovery_cli_rejects_item_limit_above_public_hard_boundary() -> None:
    result = RUNNER.invoke(
        app,
        [
            "maintenance",
            "recover",
            "--run-id",
            "m3-recovery-limit-boundary",
            "--config",
            str(CONFIG_PATH),
            "--json",
            "--max-items",
            "1001",
        ],
    )

    assert result.exit_code == 2
