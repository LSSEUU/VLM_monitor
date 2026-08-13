from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

from labcourt.adapters.storage.sqlite_m8_operations_repository import (
    SQLiteM8OperationsRepository,
)
from labcourt.application.m8_platform_bootstrap import PLATFORM_DATABASE_NAME, platform_manifest
from labcourt.application.m8_platform_demo_api import assemble_m8_platform_demo_api
from labcourt.contracts.m8_access_cases import M8ActorRole
from labcourt.contracts.m8_feishu_live import (
    M8FeishuDutyRouteV1,
    M8FeishuLiveConnectionState,
    M8FeishuRuntimeHeartbeatV1,
    M8FeishuWorkerState,
)
from labcourt.services.m8_feishu_live_api import M8FeishuLiveApiService
from tests.integration.test_m8_platform_demo_api import _login, _request
from tests.integration.test_m8_platform_knowledge_agent_feishu import _feishu_service


def _assembly(tmp_path: Path):
    media = tmp_path / "fixture.mp4"
    media.write_bytes(b"\x00\x00\x00\x18ftypisom\x00\x00\x02\x00isomiso2" + b"\x00" * 40)
    return assemble_m8_platform_demo_api(
        project_root=Path(__file__).parents[2],
        database_path=tmp_path / PLATFORM_DATABASE_NAME,
        input_media_path=media,
        port=0,
    )


def test_runtime_http_is_honest_when_unconfigured_and_channel_is_actor_scoped(
    tmp_path: Path,
    socket_enabled: None,
) -> None:
    assembly = _assembly(tmp_path)
    server = assembly.server
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        operations = _login(server.server_port, "OPERATIONS")
        student = _login(server.server_port, "STUDENT")
        status_code, status = _request(
            server.server_port,
            "GET",
            "/api/m8/integrations/feishu/runtime-status",
            token=operations,
        )
        assert status_code == 200 and isinstance(status, dict)
        assert status["platform"]["display_status"] == "NOT_CONFIGURED"
        assert status["live_dispatch_available"] is False
        assert status["connection"] is None
        assert status["authority_worker"] is None
        assert status["delivery_worker"] is None

        denied, _ = _request(
            server.server_port,
            "GET",
            "/api/m8/integrations/feishu/runtime-status",
            token=student,
        )
        assert denied == 403
        route_code, route = _request(
            server.server_port,
            "GET",
            "/api/m8/integrations/feishu/duty-route",
            token=operations,
        )
        assert route_code == 200 and route is None

        created_code, created = _request(
            server.server_port,
            "POST",
            "/api/m8/agent/conversations",
            token=operations,
            payload={},
        )
        assert created_code == 201 and isinstance(created, dict)
        channel_code, channel = _request(
            server.server_port,
            "GET",
            "/api/m8/agent/conversations/"
            f"{created['conversation_id']}/channel-projection",
            token=operations,
        )
        assert channel_code == 200 and channel is None
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_runtime_status_requires_active_platform_route_and_all_fresh_workers(
    tmp_path: Path,
    socket_enabled: None,
) -> None:
    assembly = _assembly(tmp_path)
    server = assembly.server
    token = server.platform_role_tokens[M8ActorRole.OPERATIONS]
    principal = server.api_authenticator.authenticate(f"Bearer {token}")
    operations = SQLiteM8OperationsRepository(
        assembly.database_path,
        5_000,
        platform_manifest("labcourt-platform-sqlite-repository-v1"),
    )
    safety = operations.get_current_actor_authority("safety-officer-demo")
    platform = _feishu_service(active=True).status()
    assert platform.activation_revision is not None
    assert platform.activation_status_id is not None
    now = datetime.now(UTC)
    route = assembly.feishu_live.repository.commit_duty_route(
        M8FeishuDutyRouteV1(
            actor_id=safety.authority.actor_id,
            actor_authority_commit_receipt_id=safety.commit_receipt_id,
            recipient_binding_authority_id="a" * 64,
            activation_revision=platform.activation_revision,
            activation_status_id=platform.activation_status_id,
            route_revision=1,
            committed_at=now,
            repository_manifest_id=platform_manifest(
                "platform-feishu-live-repository-v1"
            ),
        )
    )
    for heartbeat in (
        M8FeishuRuntimeHeartbeatV1(
            component="LONG_CONNECTION",
            connection_state=M8FeishuLiveConnectionState.READY,
            observed_at=now,
            runtime_manifest_id="b" * 64,
        ),
        M8FeishuRuntimeHeartbeatV1(
            component="AUTHORITY_WORKER",
            worker_state=M8FeishuWorkerState.READY,
            observed_at=now,
            runtime_manifest_id="c" * 64,
        ),
        M8FeishuRuntimeHeartbeatV1(
            component="DELIVERY_WORKER",
            worker_state=M8FeishuWorkerState.READY,
            observed_at=now,
            runtime_manifest_id="d" * 64,
        ),
    ):
        assembly.feishu_live.repository.record_heartbeat(heartbeat)
    current_time = [now]
    api = M8FeishuLiveApiService(
        assembly.feishu_live.repository,
        server.api_service,
        server.notification_service,
        lambda: platform,
        operations.get_current_actor_authority,
        lambda _binding: (_ for _ in ()).throw(ValueError("not required")),
        assembly.feishu_live.alert_bridge,
        None,
        lambda: current_time[0],
        platform_manifest("platform-feishu-live-repository-v1"),
    )

    status = api.runtime_status(principal)
    assert status.live_dispatch_available is True
    assert status.duty_route == route

    busy_at = now + timedelta(seconds=1)
    for heartbeat in (
        M8FeishuRuntimeHeartbeatV1(
            component="AUTHORITY_WORKER",
            worker_state=M8FeishuWorkerState.BUSY,
            observed_at=busy_at,
            runtime_manifest_id="c" * 64,
        ),
        M8FeishuRuntimeHeartbeatV1(
            component="DELIVERY_WORKER",
            worker_state=M8FeishuWorkerState.BUSY,
            observed_at=busy_at,
            runtime_manifest_id="d" * 64,
        ),
    ):
        assembly.feishu_live.repository.record_heartbeat(heartbeat)
    current_time[0] = busy_at
    assert api.runtime_status(principal).live_dispatch_available is True
