from __future__ import annotations

import hashlib
import http.client
import json
import threading
from pathlib import Path

from labcourt.application.m8_platform_bootstrap import (
    PLATFORM_CAMERA_ID,
    PLATFORM_CAMPUS_ID,
    PLATFORM_DATABASE_NAME,
    PLATFORM_LOCATION_ID,
    load_m8_platform_bootstrap,
    platform_manifest,
)
from labcourt.application.m8_platform_demo_api import assemble_m8_platform_demo_api
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m8_access_cases import (
    M8AuthorityReference,
    M8AuthorityReferenceKind,
    M8OperationalCaseCreateCommandV1,
    M8OperationalRiskLevel,
)
from labcourt.contracts.m8_platform_demo import (
    M8PlatformRecognitionMode,
    M8PlatformScenarioKind,
    M8PlatformScenarioRunV1,
    M8PlatformScenarioStage,
    M8PlatformScenarioStageV1,
    M8PlatformStageState,
)
from labcourt.contracts.pilot_ui import PilotUiJobStatus
from labcourt.services.pilot_progress import PilotProgressUpdate


def _request(
    port: int,
    method: str,
    path: str,
    *,
    token: str | None = None,
    payload: object | None = None,
) -> tuple[int, object]:
    body = None if payload is None else canonical_json(payload).encode("utf-8")
    headers = {"Origin": f"http://127.0.0.1:{port}"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    if body is not None:
        headers["Content-Type"] = "application/json"
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    content = response.read()
    connection.close()
    return response.status, json.loads(content) if content else None


def _range_request(port: int, path: str) -> tuple[int, bytes, str | None]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    connection.request("GET", path, headers={"Range": "bytes=0-31"})
    response = connection.getresponse()
    content = response.read()
    content_range = response.getheader("Content-Range")
    connection.close()
    return response.status, content, content_range


def _login(port: int, role: str) -> str:
    status, payload = _request(
        port,
        "POST",
        "/api/m8/demo/login",
        payload={"role": role},
    )
    assert status == 200
    assert isinstance(payload, dict)
    assert payload["personal_demo_only"] is True
    assert payload["production_ready"] is False
    return str(payload["bearer_token"])


def _assembly(tmp_path: Path):
    root = Path(__file__).parents[2]
    return assemble_m8_platform_demo_api(
        project_root=root,
        database_path=tmp_path / PLATFORM_DATABASE_NAME,
        input_media_path=root / "inputs/goggles-missing.mp4",
        port=0,
    )


def _transition_payload(
    case: dict[str, object],
    *,
    action: str,
    reason_code: str,
    additional_authorities: tuple[dict[str, object], ...] = (),
    appeal_resolution: str | None = None,
) -> dict[str, object]:
    audit = case["audit_event"]
    assert isinstance(audit, dict)
    authority = audit["case_authority"]
    assert isinstance(authority, dict)
    create_command = authority["create_command"]
    assert isinstance(create_command, dict)
    triggers = create_command["trigger_authorities"]
    assert isinstance(triggers, list)
    supporting = [*triggers, *additional_authorities]
    supporting.sort(
        key=lambda item: (
            str(item["kind"]),
            str(item["authority_id"]),
            str(item["document_sha256"]),
        )
    )
    return {
        "source_case_version": case["case_version"],
        "source_case_authority_sha256": case["case_document_sha256"],
        "source_status": case["status"],
        "case_location_id": authority["location_id"],
        "subject_actor_id": authority["subject_actor_id"],
        "action": action,
        "reason_code": reason_code,
        "reason_summary": "Explicit human action in the platform Demo integration test.",
        "supporting_authorities": supporting,
        "appeal_resolution": appeal_resolution,
        "explicit_human_confirmation": True,
        "command_manifest_id": hashlib.sha256(
            b"labcourt-platform-test-human-command-v1"
        ).hexdigest(),
    }


def test_platform_login_rbac_static_routes_and_sensor_emergency(
    tmp_path: Path,
    socket_enabled: None,
) -> None:
    assembly = _assembly(tmp_path)
    server = assembly.server
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        for path in ("/", "/login", "/app/monitor", "/app/cases/example"):
            connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
            connection.request("GET", path)
            response = connection.getresponse()
            assert response.status == 200
            assert response.getheader("Content-Type") == "text/html; charset=utf-8"
            assert b"LabCourt" in response.read()
            connection.close()

        leader = _login(server.server_port, "LEADER")
        operations = _login(server.server_port, "OPERATIONS")
        student = _login(server.server_port, "STUDENT")
        media_status, media_bytes, content_range = _range_request(
            server.server_port, "/api/m8/demo/public-media/recorded-video"
        )
        assert media_status == 206
        assert len(media_bytes) == 32
        assert content_range is not None and content_range.startswith("bytes 0-31/")
        head = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
        head.request("HEAD", "/api/m8/demo/public-media/recorded-video")
        head_response = head.getresponse()
        assert head_response.status == 200
        assert int(head_response.getheader("Content-Length", "0")) > 0
        assert head_response.read() == b""
        head.close()
        readiness_status, readiness = _request(
            server.server_port,
            "GET",
            "/api/m8/demo/model-readiness",
            token=operations,
        )
        assert readiness_status == 200
        assert isinstance(readiness, dict)
        assert readiness["automatic_fallback_permitted"] is False
        assert [item["component"] for item in readiness["components"]] == [
            "PERCEPTION",
            "SCREENING",
        ]
        denied, _ = _request(
            server.server_port,
            "POST",
            "/api/m8/demo/scenario-runs",
            token=leader,
            payload={
                "scenario_kind": "SMOKE_TEMPERATURE_EMERGENCY",
                "explicit_human_confirmation": True,
            },
        )
        assert denied == 403

        agent_status, action_card = _request(
            server.server_port,
            "POST",
            "/api/m8/agent/queries",
            token=operations,
            payload={"query": "请触发烟雾和温度场景"},
        )
        assert agent_status == 200
        assert isinstance(action_card, dict)
        proposed_action = action_card["proposed_action"]
        assert proposed_action["action_kind"] == "RUN_SCENARIO"
        assert proposed_action["current_version"] == 1
        assert proposed_action["requires_confirmation"] is True

        started, run = _request(
            server.server_port,
            "POST",
            "/api/m8/demo/scenario-runs",
            token=operations,
            payload=proposed_action["request_payload"],
        )
        assert started == 202
        assert isinstance(run, dict)
        assert run["state"] == "SUCCEEDED"
        assert run["case_status"] == "PENDING_VERIFICATION"
        assert run["rule_judgment"] == "EMERGENCY"
        assert run["simulated"] is True
        assert [item["state"] for item in run["stages"]] == ["COMPLETE"] * 6

        case_status, cases = _request(
            server.server_port, "GET", "/api/m8/cases", token=leader
        )
        assert case_status == 200
        assert isinstance(cases, list) and cases[0]["status"] == "PENDING_VERIFICATION"
        student_case_status, student_cases = _request(
            server.server_port, "GET", "/api/m8/cases", token=student
        )
        assert student_case_status == 200
        assert student_cases == []

        safety = _login(server.server_port, "SAFETY_OFFICER")
        agent_status, action_card = _request(
            server.server_port,
            "POST",
            "/api/m8/agent/queries",
            token=safety,
            payload={"query": "请确认并处置当前案件"},
        )
        assert agent_status == 200
        assert isinstance(action_card, dict)
        proposed_action = action_card["proposed_action"]
        assert proposed_action["action_kind"] == "CASE_TRANSITION"
        assert proposed_action["target_ref"] == cases[0]["case_id"]
        assert proposed_action["current_version"] == 1
        confirmed_status, confirmed = _request(
            server.server_port,
            "POST",
            f"/api/m8/cases/{cases[0]['case_id']}/transitions",
            token=safety,
            payload=_transition_payload(
                cases[0], action="CONFIRM", reason_code="VERIFIED_VIOLATION"
            ),
        )
        assert confirmed_status == 200
        assert isinstance(confirmed, dict) and confirmed["status"] == "CONFIRMED"
        resolved_status, resolved = _request(
            server.server_port,
            "POST",
            f"/api/m8/cases/{cases[0]['case_id']}/transitions",
            token=safety,
            payload=_transition_payload(
                confirmed, action="RESOLVE", reason_code="HAZARD_CLEARED"
            ),
        )
        assert resolved_status == 200
        assert isinstance(resolved, dict) and resolved["status"] == "RESOLVED"

        projection_status, projection = _request(
            server.server_port,
            "GET",
            "/api/m8/campuses/campus-demo/operations-projection",
            token=operations,
        )
        assert projection_status == 200
        assert isinstance(projection, dict)
        source_views = projection["visible_projection"]["sources"]
        sensor_values = {
            item["source"]["sensor_type"]: item["latest_sample_receipt"]["sample"]["value"]
            for item in source_views
            if item["latest_sample_receipt"] is not None
        }
        assert sensor_values == {"SMOKE": True, "TEMPERATURE": 82_000}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_platform_fixture_fallback_is_explicit_and_preserves_failed_model_run(
    tmp_path: Path,
    socket_enabled: None,
    monkeypatch,
) -> None:
    assembly = _assembly(tmp_path)
    platform = assembly.server.platform_service
    stages = tuple(
        M8PlatformScenarioStageV1(
            stage=stage,
            state=M8PlatformStageState.PENDING,
            summary="尚未生成",
        )
        for stage in M8PlatformScenarioStage
    )
    running = M8PlatformScenarioRunV1(
        run_id="platform-full-running",
        scenario_kind=M8PlatformScenarioKind.PPE_GOGGLES_MISSING,
        state="RUNNING",
        stages=stages,
        recognition_mode=M8PlatformRecognitionMode.FULL_MODEL,
    )
    platform._write_run(running)
    monkeypatch.setattr(platform.fixture_pilot_jobs, "start", lambda _request: None)
    server = assembly.server
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        operations = _login(server.server_port, "OPERATIONS")
        rejected, _ = _request(
            server.server_port,
            "POST",
            "/api/m8/demo/scenario-runs",
            token=operations,
            payload={
                "scenario_kind": "PPE_GOGGLES_MISSING",
                "recognition_mode": "DEMO_FIXTURE",
                "retry_of_run_id": running.run_id,
                "explicit_human_confirmation": True,
            },
        )
        assert rejected == 400

        failed = running.model_copy(
            update={"state": "FAILED", "failure_code": "PERCEPTION_WORKER_FAILED"}
        )
        platform._write_run(failed)
        accepted, fallback = _request(
            server.server_port,
            "POST",
            "/api/m8/demo/scenario-runs",
            token=operations,
            payload={
                "scenario_kind": "PPE_GOGGLES_MISSING",
                "recognition_mode": "DEMO_FIXTURE",
                "retry_of_run_id": failed.run_id,
                "explicit_human_confirmation": True,
            },
        )
        assert accepted == 202
        assert isinstance(fallback, dict)
        assert fallback["recognition_mode"] == "DEMO_FIXTURE"
        assert fallback["retry_of_run_id"] == failed.run_id
        assert fallback["run_id"] != failed.run_id
        preserved = platform._read_run_snapshot(failed.run_id)
        assert preserved.state == "FAILED"
        assert preserved.failure_code == "PERCEPTION_WORKER_FAILED"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_platform_projects_truthful_hot_progress_and_failure_stage(
    tmp_path: Path,
    socket_enabled: None,
    monkeypatch,
) -> None:
    assembly = _assembly(tmp_path)
    platform = assembly.server.platform_service
    running = M8PlatformScenarioRunV1(
        run_id="platform-progress",
        scenario_kind=M8PlatformScenarioKind.PPE_GOGGLES_MISSING,
        state="RUNNING",
        stages=tuple(
            M8PlatformScenarioStageV1(
                stage=stage,
                state=("RUNNING" if stage == M8PlatformScenarioStage.VIDEO else "PENDING"),
                summary="waiting",
            )
            for stage in M8PlatformScenarioStage
        ),
        recognition_mode=M8PlatformRecognitionMode.FULL_MODEL,
    )
    progress = (
        PilotProgressUpdate(stage="VIDEO", state="COMPLETE"),
        PilotProgressUpdate(
            stage="PERCEPTION",
            state="COMPLETE",
            completed_units=241,
            total_units=241,
            unit="FRAME",
        ),
        PilotProgressUpdate(stage="EVIDENCE", state="COMPLETE"),
        PilotProgressUpdate(stage="SCREENING", state="RUNNING"),
    )

    projected = platform._project_ppe_progress(running, progress, "SCREENING")
    perception = projected.stages[1]
    assert tuple(item.state for item in projected.stages) == (
        "COMPLETE",
        "COMPLETE",
        "COMPLETE",
        "RUNNING",
        "PENDING",
        "PENDING",
    )
    assert (perception.completed_units, perception.total_units, perception.unit) == (
        241,
        241,
        "FRAME",
    )

    failed = platform._failed_ppe_run(
        projected,
        failure_code="SCREENING_FAILED",
        failed_stage=platform._pilot_failure_stage(
            "SCREENING_FAILED",
            progress,
            projected,
        ),
    )
    assert failed.state == "FAILED"
    assert failed.stages[3].state == "FAILED"
    assert failed.stages[4].state == "PENDING"
    assert failed.stages[1].completed_units == 241

    perception_running = platform._project_ppe_progress(
        running,
        (
            PilotProgressUpdate(stage="VIDEO", state="COMPLETE"),
            PilotProgressUpdate(
                stage="PERCEPTION",
                state="RUNNING",
                completed_units=7,
                total_units=241,
                unit="FRAME",
            ),
        ),
        "PERCEPTION",
    )
    hotter_progress = (
        PilotProgressUpdate(stage="VIDEO", state="COMPLETE"),
        PilotProgressUpdate(
            stage="PERCEPTION",
            state="RUNNING",
            completed_units=8,
            total_units=241,
            unit="FRAME",
        ),
    )
    job = PilotUiJobStatus(
        job_id="job-platform-progress",
        state="RUNNING",
        run_id=running.run_id,
        video_id="a" * 64,
        active_stage="PERCEPTION",
    )

    class _RunningJobs:
        @staticmethod
        def snapshot():
            return job

        @staticmethod
        def progress_snapshot():
            return hotter_progress

    writes: list[M8PlatformScenarioRunV1] = []
    monkeypatch.setattr(platform, "_pilot_jobs_for", lambda _run: _RunningJobs())
    monkeypatch.setattr(platform, "_write_run", writes.append)
    refreshed = platform._refresh_ppe(perception_running)
    assert refreshed.stages[1].completed_units == 8
    assert writes == []  # hot frame updates remain visible without per-frame disk writes

    attention_job = PilotUiJobStatus(
        job_id="job-platform-attention",
        state="ATTENTION_REQUIRED",
        run_id=running.run_id,
        video_id="a" * 64,
        report_id="b" * 64,
    )

    class _AttentionJobs:
        @staticmethod
        def snapshot():
            return attention_job

        @staticmethod
        def progress_snapshot():
            return progress

    screening_failed = platform._failed_ppe_run(
        projected,
        failure_code="SCREENING_PROVIDER_UNAVAILABLE",
        failed_stage=M8PlatformScenarioStage.SCREENING,
    ).model_copy(
        update={
            "model_components": (),
            "outcome": None,
            "case_id": None,
            "case_status": None,
            "notification_id": None,
        }
    )
    monkeypatch.setattr(platform, "_pilot_jobs_for", lambda _run: _AttentionJobs())
    monkeypatch.setattr(
        platform,
        "_finalize_attention_required_ppe",
        lambda _run: screening_failed,
    )
    monkeypatch.setattr(
        platform,
        "_finalize_ppe",
        lambda _run: (_ for _ in ()).throw(AssertionError("must not finalize a case")),
    )
    refreshed_attention = platform._refresh_ppe(running)
    assert refreshed_attention.failure_code == "SCREENING_PROVIDER_UNAVAILABLE"
    assert refreshed_attention.stages[3].state == "FAILED"
    assert refreshed_attention.stages[4].state == "PENDING"
    assert refreshed_attention.case_id is None
    assert refreshed_attention.notification_id is None

    completed_stages = tuple(
        M8PlatformScenarioStageV1(
            stage=stage,
            state="COMPLETE",
            summary="complete",
        )
        for stage in M8PlatformScenarioStage
    )
    preserved = platform._preserve_perception_progress(completed_stages, projected)
    assert preserved[1].completed_units == preserved[1].total_units == 241
    assembly.server.server_close()


def test_platform_notification_appeal_outcome_and_acknowledgement_closure(
    tmp_path: Path,
    socket_enabled: None,
) -> None:
    assembly = _assembly(tmp_path)
    platform = assembly.server.platform_service
    bootstrap = load_m8_platform_bootstrap(tmp_path)
    catalog = platform._inventory().get_current_source_catalog(PLATFORM_CAMPUS_ID)
    seeded = platform._operations().create_operational_case(
        M8OperationalCaseCreateCommandV1(
            source_catalog_id=catalog.catalog.catalog_id,
            location_id=PLATFORM_LOCATION_ID,
            risk_level=M8OperationalRiskLevel.GENERAL,
            policy_rule_id="platform-notification-closure-fixture-v1",
            policy_manifest_id=platform_manifest("platform-notification-policy-v1"),
            source_ids=(PLATFORM_CAMERA_ID,),
            simulated_source_ids=(PLATFORM_CAMERA_ID,),
            trigger_authorities=(
                M8AuthorityReference(
                    kind=M8AuthorityReferenceKind.RESERVATION,
                    authority_id=bootstrap.reservation.reservation_id,
                    document_sha256=hashlib.sha256(
                        canonical_json(
                            bootstrap.reservation.model_dump(mode="json")
                        ).encode("utf-8")
                    ).hexdigest(),
                ),
            ),
            automation_component_id="m8-platform-notification-closure-fixture",
            automation_manifest_id=platform_manifest(
                "platform-notification-closure-fixture-v1"
            ),
        ),
        "student-demo",
        platform_manifest("platform-case-authority-v1"),
        platform_manifest("platform-case-audit-v1"),
    )
    server = assembly.server
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        safety = _login(server.server_port, "SAFETY_OFFICER")
        student = _login(server.server_port, "STUDENT")
        case_status, current = _request(
            server.server_port,
            "GET",
            f"/api/m8/cases/{seeded.case_id}",
            token=safety,
        )
        assert case_status == 200 and isinstance(current, dict)
        confirm_status, confirmed = _request(
            server.server_port,
            "POST",
            f"/api/m8/cases/{seeded.case_id}/transitions",
            token=safety,
            payload=_transition_payload(
                current, action="CONFIRM", reason_code="VERIFIED_VIOLATION"
            ),
        )
        assert confirm_status == 200 and isinstance(confirmed, dict)

        dispatch_status, original = _request(
            server.server_port,
            "POST",
            f"/api/m8/cases/{seeded.case_id}/notification-dispatches",
            token=safety,
            payload={"kind": "CASE_UPDATED", "explicit_human_confirmation": True},
        )
        assert dispatch_status == 200 and isinstance(original, dict)
        assert original["status"] == "DELIVERED"
        delivery = original["audit_event"]["transition_command"]["delivery_receipt"]
        assert delivery["real_delivery_confirmed"] is False

        reply_status, reply = _request(
            server.server_port,
            "POST",
            f"/api/m8/notifications/{original['notification_id']}/replies",
            token=student,
            payload={
                "reply_kind": "APPEAL_REQUEST",
                "body": "我请求人工复核录像证据与预约关联。",
                "explicit_human_confirmation": True,
            },
        )
        assert reply_status == 200 and isinstance(reply, dict)
        reply_authority = reply["audit_event"]["transition_command"]["reply"]
        appeal_status, appealed = _request(
            server.server_port,
            "POST",
            f"/api/m8/cases/{seeded.case_id}/transitions",
            token=student,
            payload=_transition_payload(
                confirmed,
                action="SUBMIT_APPEAL",
                reason_code="SUBJECT_DISPUTE",
                additional_authorities=(
                    {
                        "kind": "NOTIFICATION_REPLY",
                        "authority_id": reply_authority["reply_authority_id"],
                        "document_sha256": reply_authority["reply_document_sha256"],
                    },
                ),
            ),
        )
        assert appeal_status == 200 and isinstance(appealed, dict)
        assert appealed["status"] == "APPEALED"
        resolution_status, resolved = _request(
            server.server_port,
            "POST",
            f"/api/m8/cases/{seeded.case_id}/transitions",
            token=safety,
            payload=_transition_payload(
                appealed,
                action="RESOLVE_APPEAL",
                reason_code="APPEAL_OVERTURNED",
                appeal_resolution="OVERTURNED",
            ),
        )
        assert resolution_status == 200 and isinstance(resolved, dict)
        assert resolved["status"] == "APPEAL_RESOLVED"

        outcome_status, outcome = _request(
            server.server_port,
            "POST",
            f"/api/m8/cases/{seeded.case_id}/notification-dispatches",
            token=safety,
            payload={"kind": "APPEAL_OUTCOME", "explicit_human_confirmation": True},
        )
        assert outcome_status == 200 and isinstance(outcome, dict)
        assert outcome["notification_id"] != original["notification_id"]
        acknowledgement_status, acknowledgement = _request(
            server.server_port,
            "POST",
            f"/api/m8/notifications/{outcome['notification_id']}/acknowledgements",
            token=student,
            payload={"explicit_human_confirmation": True},
        )
        assert acknowledgement_status == 200
        assert isinstance(acknowledgement, dict)
        assert acknowledgement["status"] == "ACKNOWLEDGED"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_platform_reset_archives_session_and_restores_empty_baseline(
    tmp_path: Path,
    socket_enabled: None,
) -> None:
    assembly = _assembly(tmp_path)
    server = assembly.server
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        operations = _login(server.server_port, "OPERATIONS")
        _request(
            server.server_port,
            "POST",
            "/api/m8/demo/scenario-runs",
            token=operations,
            payload={
                "scenario_kind": "SMOKE_TEMPERATURE_EMERGENCY",
                "explicit_human_confirmation": True,
            },
        )
        denied, _ = _request(
            server.server_port,
            "POST",
            "/api/m8/demo/reset",
            token=_login(server.server_port, "SAFETY_OFFICER"),
            payload={"explicit_human_confirmation": True},
        )
        assert denied == 403

        status, result = _request(
            server.server_port,
            "POST",
            "/api/m8/demo/reset",
            token=operations,
            payload={"explicit_human_confirmation": True},
        )
        assert status == 200
        assert isinstance(result, dict)
        assert result["baseline_summary"] == {
            "locations": 4,
            "sources": 3,
            "cases": 0,
            "notifications": 0,
        }
        assert (tmp_path / result["archive_ref"] / PLATFORM_DATABASE_NAME).is_file()
        cases_status, cases = _request(
            server.server_port, "GET", "/api/m8/cases", token=operations
        )
        notifications_status, notifications = _request(
            server.server_port, "GET", "/api/m8/notifications", token=operations
        )
        assert cases_status == notifications_status == 200
        assert cases == notifications == []
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
