from __future__ import annotations

import http.client
import json
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

from labcourt.adapters.storage.sqlite_m8_evaluation_repository import (
    SQLiteM8EvaluationRepository,
)
from labcourt.application.m8_platform_bootstrap import (
    PLATFORM_DATABASE_NAME,
    platform_manifest,
)
from labcourt.application.m8_platform_demo_api import assemble_m8_platform_demo_api
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m8_evaluation import (
    M8EvaluationActualRoute,
    M8EvaluationDeliveryState,
    M8EvaluationMediaAssetV1,
    M8EvaluationMediaOrigin,
    M8EvaluationRunSourceKind,
    M8EvaluationRunState,
    M8EvaluationRunV1,
    M8RunSourceRefV1,
)


def _request(
    port: int,
    method: str,
    path: str,
    *,
    token: str | None = None,
    payload: object | None = None,
    connection: http.client.HTTPConnection,
) -> tuple[int, object]:
    body = None if payload is None else canonical_json(payload).encode("utf-8")
    headers = {"Origin": f"http://127.0.0.1:{port}"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    if payload is not None:
        headers["Content-Type"] = "application/json"
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    response_body = response.read()
    return response.status, json.loads(response_body) if response_body else None


def _login(
    port: int,
    role: str,
    connection: http.client.HTTPConnection,
) -> str:
    status, response = _request(
        port,
        "POST",
        "/api/m8/demo/login",
        payload={"role": role},
        connection=connection,
    )
    assert status == 200
    assert isinstance(response, dict)
    return str(response["bearer_token"])


def _publish_completed_run(database_path: Path) -> tuple[SQLiteM8EvaluationRepository, str]:
    repository = SQLiteM8EvaluationRepository(
        database_path,
        5_000,
        platform_manifest("labcourt-platform-sqlite-repository-v1"),
    )
    asset_id = "1" * 64
    source_manifest_id = "2" * 64
    repository.put_media(
        M8EvaluationMediaAssetV1(
            asset_id=asset_id,
            display_name="calibration-api.mp4",
            media_sha256=asset_id,
            size_bytes=1,
            relative_path=f"inputs/evaluation-{asset_id}.mp4",
            origin=M8EvaluationMediaOrigin.WEB_UPLOAD,
            codec="h264",
            width=16,
            height=16,
            fps_num=1,
            fps_den=1,
            frame_count=1,
            duration_millis=1_000,
            imported_by_actor_id="operations-demo",
            imported_at=datetime(2026, 8, 14, 8, 0, tzinfo=UTC),
            media_manifest_id=source_manifest_id,
        )
    )
    run_id = "evaluation-calibration-api"
    source = M8RunSourceRefV1(
        run_id=run_id,
        source_kind=M8EvaluationRunSourceKind.RECORDED_ASSET,
        asset_id=asset_id,
        media_sha256=asset_id,
        relative_path=f"inputs/evaluation-{asset_id}.mp4",
        frame_count=1,
        source_manifest_id=source_manifest_id,
    )
    started_at = datetime(2026, 8, 14, 8, 1, tzinfo=UTC)
    repository.put_run(
        M8EvaluationRunV1(
            run_id=run_id,
            revision=1,
            campaign_id="evaluation-campaign-calibration-api",
            source=source,
            ordinal=0,
            repetition=1,
            state=M8EvaluationRunState.SUCCEEDED,
            actual_route=M8EvaluationActualRoute.NO_CANDIDATE,
            accuracy_metrics_eligible=False,
            delivery_state=M8EvaluationDeliveryState.NOT_APPLICABLE,
            queued_at=started_at - timedelta(minutes=1),
            started_at=started_at,
            completed_at=started_at + timedelta(seconds=1),
            config_sha256="3" * 64,
            model_profile_sha256="4" * 64,
            run_manifest_id="5" * 64,
        ),
        None,
    )
    return repository, run_id


def test_calibration_same_origin_api_is_shadow_only_and_role_scoped(
    tmp_path: Path,
    socket_enabled: None,
) -> None:
    root = Path(__file__).parents[2]
    assembly = assemble_m8_platform_demo_api(
        project_root=root,
        database_path=tmp_path / PLATFORM_DATABASE_NAME,
        input_media_path=root / "inputs/goggles-missing.mp4",
        port=0,
    )
    evaluation_repository, run_id = _publish_completed_run(assembly.database_path)
    server = assembly.server
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    client = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=10)
    try:
        operations = _login(server.server_port, "OPERATIONS", client)
        safety = _login(server.server_port, "SAFETY_OFFICER", client)
        leader = _login(server.server_port, "LEADER", client)
        student = _login(server.server_port, "STUDENT", client)

        status, dashboard = _request(
            server.server_port,
            "GET",
            "/api/m8/evaluation/calibration",
            token=operations,
            connection=client,
        )
        assert status == 200
        assert isinstance(dashboard, dict)
        assert dashboard["status"] == "INSUFFICIENT_DATA"
        assert dashboard["confirmed_interval_counts"] == {
            "NOT_WORN": 0,
            "UNCLEAR": 0,
            "WORN": 0,
        }
        assert dashboard["qwen_probability_is_authority"] is False
        assert dashboard["routing_authority"] is False
        assert dashboard["activation_available"] is False

        status, dataset = _request(
            server.server_port,
            "POST",
            "/api/m8/evaluation/calibration/datasets",
            token=safety,
            payload={"explicit_human_confirmation": True},
            connection=client,
        )
        assert status == 201
        assert isinstance(dataset, dict)
        assert dataset["entries"] == []
        assert dataset["machine_output_is_ground_truth"] is False

        status, fit = _request(
            server.server_port,
            "POST",
            "/api/m8/evaluation/calibration/fits",
            token=operations,
            payload={
                "dataset_manifest_id": dataset["dataset_manifest_id"],
                "explicit_human_confirmation": True,
            },
            connection=client,
        )
        assert status == 200
        assert isinstance(fit, dict)
        assert fit["status"] == "INSUFFICIENT_DATA"
        assert fit["reason_code"] == "INSUFFICIENT_DATA"
        assert fit["artifact"] is None
        assert fit["report"] is None

        status, leader_dashboard = _request(
            server.server_port,
            "GET",
            "/api/m8/evaluation/calibration",
            token=leader,
            connection=client,
        )
        assert status == 200
        assert isinstance(leader_dashboard, dict)
        assert (
            leader_dashboard["dataset_manifest"]["dataset_manifest_id"]
            == dataset["dataset_manifest_id"]
        )

        status, forbidden = _request(
            server.server_port,
            "GET",
            "/api/m8/evaluation/calibration",
            token=student,
            connection=client,
        )
        assert status == 403
        assert isinstance(forbidden, dict)
        assert forbidden["reason_code"] == "FORBIDDEN"

        before = evaluation_repository.get_run(run_id)
        status, assessment = _request(
            server.server_port,
            "GET",
            f"/api/m8/evaluation/runs/{run_id}/risk-assessment",
            token=leader,
            connection=client,
        )
        assert status == 200
        assert isinstance(assessment, dict)
        assert assessment["evidence_quality"]["mode"] == "NOT_APPLICABLE"
        assert assessment["event_risk"]["mode"] == "NOT_APPLICABLE"
        assert assessment["evidence_quality"]["reason_code"] == "ARTIFACT_UNAVAILABLE"
        assert assessment["event_risk"]["reason_code"] == "ARTIFACT_UNAVAILABLE"
        assert assessment["qwen_probability_is_authority"] is False
        assert assessment["routing_changed"] is False
        after = evaluation_repository.get_run(run_id)
        assert after == before
        assert after.actual_route == M8EvaluationActualRoute.NO_CANDIDATE
    finally:
        client.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        assembly.evaluation_service.close()
