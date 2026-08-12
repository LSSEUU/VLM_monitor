from __future__ import annotations

import http.client
import json
import threading
from pathlib import Path

from labcourt.application.m8_platform_bootstrap import PLATFORM_DATABASE_NAME
from labcourt.application.m8_platform_demo_api import assemble_m8_platform_demo_api
from labcourt.contracts.canonical import canonical_json


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

        started, run = _request(
            server.server_port,
            "POST",
            "/api/m8/demo/scenario-runs",
            token=operations,
            payload={
                "scenario_kind": "SMOKE_TEMPERATURE_EMERGENCY",
                "explicit_human_confirmation": True,
            },
        )
        assert started == 202
        assert isinstance(run, dict)
        assert run["state"] == "SUCCEEDED"
        assert run["case_status"] == "PENDING_VERIFICATION"
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
