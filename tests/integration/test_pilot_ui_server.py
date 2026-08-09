from __future__ import annotations

import http.client
import json
import threading
from pathlib import Path

from labcourt.pilot_ui_server import build_pilot_ui_server
from tests.contract.test_pilot_a5_contracts import _report as _a5_report
from tests.integration.test_pilot_ui_service import PROJECT_ROOT, _complete_fixture


def _request(
    connection: http.client.HTTPConnection,
    method: str,
    path: str,
    *,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    connection.request(method, path, body=body, headers=headers or {})
    response = connection.getresponse()
    return response.status, dict(response.getheaders()), response.read()


def test_pilot_ui_server_delivers_same_origin_dashboard_and_range_media(
    tmp_path: Path,
    socket_enabled: None,
) -> None:
    service, _, evidence_media = _complete_fixture(tmp_path)
    del service
    server = build_pilot_ui_server(
        project_root=tmp_path,
        config_path=PROJECT_ROOT / "configs" / "pilot.yaml",
        port=0,
        runner=lambda **_: _a5_report(),
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
    try:
        status, headers, body = _request(connection, "GET", "/")
        assert status == 200
        assert "default-src 'self'" in headers["Content-Security-Policy"]
        assert "视频安全审查台" in body.decode("utf-8")

        status, _, body = _request(
            connection,
            "GET",
            "/api/dashboard?run_id=pilot-001",
        )
        assert status == 200
        dashboard = json.loads(body)
        assert dashboard["selected_run_id"] == "pilot-001"
        assert dashboard["production_delivery_count"] == 0

        video_id = dashboard["videos"][0]["video_id"]
        status, headers, body = _request(
            connection,
            "GET",
            f"/api/videos/{video_id}",
            headers={"Range": "bytes=0-6"},
        )
        assert status == 206
        assert headers["Content-Range"].startswith("bytes 0-6/")
        assert body == b"bounded"

        crop_id = dashboard["cases"][0]["evidence"][0]["crop_id"]
        status, headers, body = _request(
            connection,
            "GET",
            f"/api/runs/pilot-001/evidence/{crop_id}",
        )
        assert status == 200
        assert headers["Content-Type"] == "image/png"
        assert body == evidence_media

        request = json.dumps({"video_id": video_id, "run_id": "pilot-001", "resume": True}).encode(
            "utf-8"
        )
        status, _, body = _request(
            connection,
            "POST",
            "/api/jobs",
            body=request,
            headers={"Content-Type": "application/json"},
        )
        assert status == 202
        assert json.loads(body)["state"] == "RUNNING"
        assert server.ui_jobs.wait(timeout=2).state == "SUCCEEDED"
    finally:
        connection.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_pilot_ui_server_rejects_non_local_host(
    tmp_path: Path,
    socket_enabled: None,
) -> None:
    _complete_fixture(tmp_path)
    server = build_pilot_ui_server(
        project_root=tmp_path,
        config_path=PROJECT_ROOT / "configs" / "pilot.yaml",
        port=0,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
    try:
        status, _, body = _request(
            connection,
            "GET",
            "/api/dashboard",
            headers={"Host": "attacker.example"},
        )
        assert status == 403
        assert json.loads(body)["reason_code"] == "LOCAL_HOST_REQUIRED"
    finally:
        connection.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
