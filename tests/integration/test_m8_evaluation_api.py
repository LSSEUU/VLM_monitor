from __future__ import annotations

import hashlib
import http.client
import json
import threading
from pathlib import Path

from labcourt.application.m8_platform_bootstrap import PLATFORM_DATABASE_NAME
from labcourt.application.m8_platform_demo_api import assemble_m8_platform_demo_api
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m8_evaluation import (
    M8EvaluationRunSourceKind,
    M8RunSourceRefV1,
)


def _request(
    port: int,
    method: str,
    path: str,
    *,
    token: str | None = None,
    payload: object | None = None,
    body: bytes | None = None,
    content_type: str | None = None,
    connection: http.client.HTTPConnection | None = None,
) -> tuple[int, object]:
    if payload is not None:
        body = canonical_json(payload).encode("utf-8")
        content_type = "application/json"
    headers = {"Origin": f"http://127.0.0.1:{port}"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    if content_type is not None:
        headers["Content-Type"] = content_type
    client = connection or http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    client.request(method, path, body=body, headers=headers)
    response = client.getresponse()
    response_body = response.read()
    if connection is None:
        client.close()
    return response.status, json.loads(response_body) if response_body else None


def _login(port: int, role: str, connection: http.client.HTTPConnection) -> str:
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


def test_evaluation_api_upload_deduplicates_and_enforces_roles(
    tmp_path: Path,
    socket_enabled: None,
    monkeypatch,
) -> None:
    root = Path(__file__).parents[2]
    source = root / "inputs/goggles-missing.mp4"
    media = source.read_bytes()
    digest = hashlib.sha256(media).hexdigest()
    controlled = root / f"inputs/evaluation-{digest}.mp4"
    controlled_preexisted = controlled.exists()
    assembly = assemble_m8_platform_demo_api(
        project_root=root,
        database_path=tmp_path / PLATFORM_DATABASE_NAME,
        input_media_path=source,
        port=0,
    )
    server = assembly.server
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    client = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=10)
    try:
        operations = _login(server.server_port, "OPERATIONS", client)
        safety = _login(server.server_port, "SAFETY_OFFICER", client)
        leader = _login(server.server_port, "LEADER", client)
        student = _login(server.server_port, "STUDENT", client)

        status, _ = _request(
            server.server_port,
            "GET",
            "/api/m8/evaluation/dashboard",
            token=student,
            connection=client,
        )
        assert status == 403

        boundary = "labcourt-evaluation-boundary"
        multipart = (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="file"; filename="clear-ppe.mp4"\r\n'
            "Content-Type: video/mp4\r\n\r\n"
        ).encode("ascii") + media + f"\r\n--{boundary}--\r\n".encode("ascii")
        status, asset = _request(
            server.server_port,
            "POST",
            "/api/m8/evaluation/media/uploads",
            token=operations,
            body=multipart,
            content_type=f"multipart/form-data; boundary={boundary}",
            connection=client,
        )
        assert status == 201
        assert isinstance(asset, dict)
        assert asset["asset_id"] == digest
        assert asset["media_sha256"] == digest
        assert asset["machine_output_is_ground_truth"] is False

        source_ref = M8RunSourceRefV1(
            run_id="evaluation-source-binding",
            source_kind=M8EvaluationRunSourceKind.RECORDED_ASSET,
            asset_id=digest,
            media_sha256=digest,
            relative_path=asset["relative_path"],
            frame_count=asset["frame_count"],
            source_manifest_id=asset["media_manifest_id"],
        )
        monkeypatch.setattr(
            assembly.server.platform_service.model_pilot_jobs,
            "start",
            lambda _request: None,
        )
        scenario = assembly.server.platform_service.start_evaluation_scenario(source_ref)
        assert scenario.run_id == source_ref.run_id
        assert (
            assembly.server.platform_service._run_input_relative_path(source_ref.run_id)
            == source_ref.relative_path
        )
        client.request(
            "GET",
            f"/api/m8/demo/scenario-runs/{source_ref.run_id}/source-video",
            headers={
                "Authorization": f"Bearer {operations}",
                "Range": "bytes=0-31",
            },
        )
        media_response = client.getresponse()
        assert media_response.status == 206
        assert media_response.read() == media[:32]

        status, imported = _request(
            server.server_port,
            "POST",
            "/api/m8/evaluation/media/imports",
            token=operations,
            payload={
                "relative_paths": ["inputs/goggles-missing.mp4"],
                "explicit_human_confirmation": True,
            },
            connection=client,
        )
        assert status == 201
        assert isinstance(imported, list)
        assert imported[0]["asset_id"] == digest

        status, truth = _request(
            server.server_port,
            "PUT",
            f"/api/m8/evaluation/media/{digest}/ground-truth",
            token=safety,
            payload={
                "asset_id": digest,
                "revision": 1,
                "violation_type": "PPE_GOGGLES_MISSING",
                "evidence_class": "ABSENCE",
                "intervals": [
                    {
                        "start_frame": 0,
                        "end_frame_exclusive": asset["frame_count"],
                        "ppe_state": "WORN",
                    }
                ],
                "expected_route": "NO_CANDIDATE",
                "review_state": "HUMAN_CONFIRMED",
                "reviewer_actor_id": "safety-officer-demo",
                "reviewed_at": "2026-08-13T08:00:00Z",
                "label_manifest_id": "a" * 64,
                "machine_output_is_ground_truth": False,
            },
            connection=client,
        )
        assert status == 200
        assert isinstance(truth, dict)
        assert truth["review_state"] == "HUMAN_CONFIRMED"

        campaign_payload = {
            "title": "clear-video-evaluation",
            "asset_ids": [digest],
            "repetitions": 2,
            "execution_profile": "REAL_MODELS",
            "notification_delivery": "LIVE_SANDBOX",
            "explicit_human_confirmation": True,
        }
        forbidden, _ = _request(
            server.server_port,
            "POST",
            "/api/m8/evaluation/campaigns",
            token=leader,
            payload=campaign_payload,
            connection=client,
        )
        assert forbidden == 403
        created, campaign = _request(
            server.server_port,
            "POST",
            "/api/m8/evaluation/campaigns",
            token=operations,
            payload=campaign_payload,
            connection=client,
        )
        assert created == 201
        assert isinstance(campaign, dict)
        assert campaign["state"] == "DRAFT"

        leader_read, dashboard = _request(
            server.server_port,
            "GET",
            "/api/m8/evaluation/dashboard",
            token=leader,
            connection=client,
        )
        assert leader_read == 200
        assert isinstance(dashboard, dict)
        assert len(dashboard["media"]) == 1
        assert len(dashboard["ground_truth"]) == 1
    finally:
        client.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        if not controlled_preexisted and controlled.exists():
            controlled.unlink()
