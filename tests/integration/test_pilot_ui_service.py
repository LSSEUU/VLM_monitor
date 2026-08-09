from __future__ import annotations

import hashlib
import threading
from pathlib import Path

import pytest

from labcourt.contracts.alerts import AlertDecision
from labcourt.contracts.pilot import (
    PilotPerceptionArtifactReceipt,
    PilotPerceptionCompletionManifest,
    PilotPerceptionReport,
)
from labcourt.contracts.pilot_report import PilotA4Metrics, PilotLocalAlertDocument
from labcourt.contracts.pilot_ui import PilotUiJobStartRequest
from labcourt.services.pilot_ui import (
    PilotUiBoundaryError,
    PilotUiJobManager,
    PilotUiService,
)
from tests.contract.test_pilot_a5_contracts import _report as _a5_report
from tests.contract.test_pilot_contracts import _a2_report
from tests.contract.test_pilot_report_contracts import _case_view
from tests.integration.test_m5_sqlite_alert_repository import _manifest_with_stream

PROJECT_ROOT = Path(__file__).parents[2]


def _write(path: Path, data: bytes) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return data


def _receipt(run_id: str, role: str, suffix: str, data: bytes) -> PilotPerceptionArtifactReceipt:
    return PilotPerceptionArtifactReceipt(
        role=role,
        artifact_ref=f"runs/{run_id}/{suffix}",
        artifact_sha256=hashlib.sha256(data).hexdigest(),
        artifact_size_bytes=len(data),
    )


def _complete_fixture(tmp_path: Path) -> tuple[PilotUiService, bytes, bytes]:
    run_id = "pilot-001"
    input_video = b"bounded synthetic MP4 bytes"
    preview_video = b"bounded synthetic preview MP4 bytes"
    evidence_media = b"bounded synthetic PNG bytes"
    _write(tmp_path / "inputs" / "demo.mp4", input_video)
    run_root = tmp_path / "runs" / run_id

    base_manifest = _manifest_with_stream()
    stream = base_manifest.streams[0].model_copy(
        update={
            "input_file_sha256": hashlib.sha256(input_video).hexdigest(),
            "fps_num": 24,
            "fps_den": 1,
            "frame_count": 24,
        }
    )
    manifest = base_manifest.model_copy(update={"streams": (stream,)})
    _write(
        run_root / "pilot" / "run-manifest.json",
        manifest.model_dump_json().encode("utf-8"),
    )

    perception = PilotPerceptionReport(
        run_id=run_id,
        frames_processed=24,
        detection_count=24,
        person_count=24,
        goggles_count=0,
        track_count=1,
        provider_failures=0,
        manifest_id="a" * 64,
        preview_path=f"runs/{run_id}/debug/perception-preview.mp4",
    )
    artifact_payloads = (
        (
            "VIDEO_MANIFEST",
            "input/video-manifest.json",
            stream.model_dump_json().encode("utf-8"),
        ),
        ("EXECUTION_MANIFEST", "perception/execution-manifest.json", b"{}\n"),
        ("FRAME_BUNDLES", "perception/frame-bundles.jsonl", b"{}\n"),
        ("FRAME_RECEIPTS", "perception/frame-receipts.jsonl", b"{}\n"),
        ("REPORT", "perception/report.json", perception.model_dump_json().encode("utf-8")),
        ("PREVIEW", "debug/perception-preview.mp4", preview_video),
    )
    receipts: list[PilotPerceptionArtifactReceipt] = []
    for role, suffix, payload in artifact_payloads:
        _write(run_root / Path(suffix), payload)
        receipts.append(_receipt(run_id, role, suffix, payload))
    completion = PilotPerceptionCompletionManifest(
        run_id=run_id,
        config_sha256=manifest.config_sha256,
        video_sha256=stream.input_file_sha256,
        manifest_id=perception.manifest_id,
        artifacts=tuple(receipts),
    )
    _write(
        run_root / "perception" / "completion-manifest.json",
        completion.model_dump_json().encode("utf-8"),
    )

    a2 = _a2_report().model_copy(
        update={
            "config_sha256": manifest.config_sha256,
            "video_sha256": stream.input_file_sha256,
            "perception_manifest_id": perception.manifest_id,
            "perception_completion_id": completion.completion_id,
            "run_manifest_id": manifest.manifest_id,
            "frames_processed": 24,
            "association_count": 24,
        }
    )
    _write(run_root / "pilot" / "a2-report.json", a2.model_dump_json().encode("utf-8"))

    media_path = run_root / "frames" / "crop.png"
    _write(media_path, evidence_media)
    source_case = _case_view()
    source_media = source_case.key_crops[0].model_copy(
        update={"media_sha256": hashlib.sha256(evidence_media).hexdigest()}
    )
    case = source_case.model_copy(
        update={"manifest_id": manifest.manifest_id, "key_crops": (source_media,)}
    )
    metrics = PilotA4Metrics(
        run_id=run_id,
        manifest_id=manifest.manifest_id,
        config_sha256=manifest.config_sha256,
        case_count=1,
        closed_count=1,
        human_review_count=0,
        established_count=1,
        not_established_count=0,
        insufficient_evidence_count=0,
        unresolved_count=0,
        verified_local_alert_count=1,
        cases=(case,),
    )
    _write(run_root / "metrics.json", metrics.model_dump_json().encode("utf-8"))
    _write(run_root / "report" / "index.html", b"<!doctype html><title>report</title>")

    alert_id = "8" * 64
    alert = PilotLocalAlertDocument(
        run_id=run_id,
        case_id=case.case_id,
        case_status="CLOSED",
        final_decision="ESTABLISHED",
        alert=AlertDecision(
            alert_id=alert_id,
            case_id=case.case_id,
            level="CONFIRMED",
            recipients=("safety-officer",),
            policy_rule_ids=("pilot-ui-test",),
        ),
        idempotency_key=alert_id,
        manifest_id=manifest.manifest_id,
        config_sha256=manifest.config_sha256,
    )
    _write(run_root / "alerts" / f"{alert_id}.json", alert.model_dump_json().encode("utf-8"))
    service = PilotUiService(
        project_root=tmp_path,
        config_path=PROJECT_ROOT / "configs" / "pilot.yaml",
    )
    return service, preview_video, evidence_media


def test_pilot_ui_projects_complete_authority_into_the_six_requested_views(
    tmp_path: Path,
) -> None:
    service, preview_video, evidence_media = _complete_fixture(tmp_path)

    dashboard = service.dashboard(run_id="pilot-001")

    assert dashboard.selected_run_id == "pilot-001"
    assert dashboard.preview_kind == "SOURCE"
    assert tuple(stage.state for stage in dashboard.stages) == ("COMPLETE",) * 5
    assert dashboard.duration_millis == 1000
    assert dashboard.videos[0].matching_run_ids == ("pilot-001",)
    assert dashboard.cases[0].case_id == "case-001"
    assert tuple(item.kind for item in dashboard.timeline) == (
        "CASE_START",
        "EVIDENCE",
        "CASE_END",
    )
    assert dashboard.alerts[0].production_action_prohibited is True
    assert service.read_evidence("pilot-001", "1" * 64).bytes == evidence_media
    assert (
        service.video_source(dashboard.videos[0].video_id).expected_sha256
        == hashlib.sha256(b"bounded synthetic MP4 bytes").hexdigest()
    )
    assert (
        service.preview_source("pilot-001").expected_sha256
        == hashlib.sha256(preview_video).hexdigest()
    )


def test_pilot_ui_fails_closed_when_previously_verified_media_changes(tmp_path: Path) -> None:
    service, _, _ = _complete_fixture(tmp_path)
    (tmp_path / "runs" / "pilot-001" / "frames" / "crop.png").write_bytes(b"tampered")

    dashboard = service.dashboard(run_id="pilot-001")

    evidence = dashboard.cases[0].evidence[0]
    assert evidence.integrity == "HASH_MISMATCH"
    assert evidence.media_url is None
    with pytest.raises(PilotUiBoundaryError, match="EVIDENCE_NOT_VERIFIED"):
        service.read_evidence("pilot-001", "1" * 64)


def test_pilot_ui_hides_internal_partial_runs_from_the_operator_selector(tmp_path: Path) -> None:
    service, _, _ = _complete_fixture(tmp_path)
    (tmp_path / "runs" / "internal-a1-only").mkdir()

    dashboard = service.dashboard(run_id="pilot-001")

    assert tuple(item.run_id for item in dashboard.runs) == ("pilot-001",)


def test_pilot_ui_job_manager_runs_the_existing_a5_boundary_once(tmp_path: Path) -> None:
    service, _, _ = _complete_fixture(tmp_path)
    release = threading.Event()
    entered = threading.Event()

    def _runner(**_: object) -> object:
        entered.set()
        assert release.wait(timeout=2)
        return _a5_report()

    manager = PilotUiJobManager(service=service, runner=_runner)
    request = PilotUiJobStartRequest(
        video_id=service.dashboard(run_id="pilot-001").videos[0].video_id,
        run_id="pilot-001",
    )

    started = manager.start(request)
    assert entered.wait(timeout=2)
    assert started.state == "RUNNING"
    with pytest.raises(PilotUiBoundaryError, match="JOB_ALREADY_RUNNING"):
        manager.start(request)

    release.set()
    assert manager.wait(timeout=2).state == "SUCCEEDED"
    assert manager.snapshot().report_id == _a5_report().report_id
