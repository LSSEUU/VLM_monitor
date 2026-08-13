"""Explicit live Feishu worker commands for the campus platform."""

from __future__ import annotations

import os
import time
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer

from labcourt.adapters.m8_feishu_lark_runtime import (
    M8FeishuLongConnectionRunner,
    build_lark_long_connection,
)
from labcourt.application.m8_platform_bootstrap import PLATFORM_DATABASE_NAME, platform_manifest
from labcourt.application.m8_platform_demo_api import (
    M8_PLATFORM_ROLE_TOKENS,
    assemble_m8_platform_demo_api,
)
from labcourt.contracts.m8_access_cases import M8ActorRole
from labcourt.contracts.m8_agent_chat import M8AgentModelAvailability
from labcourt.contracts.m8_feishu_platform import M8FeishuPlatformDisplayStatus
from labcourt.services.m8_feishu_live_ingress import M8FeishuLiveIngressService


class M8FeishuLiveComponent(StrEnum):
    LONG_CONNECTION = "LONG_CONNECTION"
    AUTHORITY_WORKER = "AUTHORITY_WORKER"
    DELIVERY_WORKER = "DELIVERY_WORKER"


def register_m8_feishu_live_commands(feishu: typer.Typer) -> None:
    @feishu.command("live-run")
    def live_run(
        component: Annotated[M8FeishuLiveComponent, typer.Option("--component")],
        output: Annotated[Path, typer.Option("--output", file_okay=False)] = Path(
            ".labcourt-local/labcourt-platform-demo"
        ),
        input_media: Annotated[
            Path,
            typer.Option("--input", exists=True, dir_okay=False),
        ] = Path("inputs/goggles-missing.mp4"),
        once: Annotated[
            bool,
            typer.Option("--once", help="Run one non-network worker cycle and exit."),
        ] = False,
        interval_ms: Annotated[
            int,
            typer.Option("--interval-ms", min=100, max=10_000),
        ] = 500,
    ) -> None:
        """Start one explicitly selected Feishu live component."""

        if once and component == M8FeishuLiveComponent.LONG_CONNECTION:
            raise typer.BadParameter("--once is not valid for the long connection")
        output.mkdir(parents=True, exist_ok=True)
        assembly = assemble_m8_platform_demo_api(
            project_root=Path(__file__).parents[2],
            database_path=output / PLATFORM_DATABASE_NAME,
            input_media_path=input_media,
            port=0,
        )
        assembly.server.server_close()
        operations_token = M8_PLATFORM_ROLE_TOKENS[M8ActorRole.OPERATIONS]
        principal = assembly.server.api_authenticator.authenticate(
            f"Bearer {operations_token}"
        )
        status = assembly.server.platform_service.feishu_status(principal)
        route = assembly.feishu_live.repository.current_duty_route()
        if (
            status.display_status != M8FeishuPlatformDisplayStatus.ACTIVE
            or route is None
            or not route.active
            or route.activation_revision != status.activation_revision
            or route.activation_status_id != status.activation_status_id
        ):
            raise typer.BadParameter(
                "Feishu live workers require ACTIVE activation and a current duty route"
            )

        if component == M8FeishuLiveComponent.LONG_CONNECTION:
            app_id = os.environ.get("LABCOURT_FEISHU_APP_ID", "")
            app_secret = os.environ.get("LABCOURT_FEISHU_APP_SECRET", "")
            ingress = M8FeishuLiveIngressService(
                assembly.feishu_live.repository,
                platform_manifest("platform-feishu-long-ingress-v1"),
            )
            client = build_lark_long_connection(
                app_id=app_id,
                app_secret=app_secret,
                ingress=ingress,
                card_executor=assembly.feishu_live.action_cards.execute,
                clock=assembly.feishu_live.clock,
            )
            M8FeishuLongConnectionRunner(
                client,
                assembly.feishu_live.repository,
                assembly.feishu_live.clock,
                platform_manifest("platform-feishu-long-connection-v1"),
            ).start()
            return

        if component == M8FeishuLiveComponent.AUTHORITY_WORKER:
            model = assembly.server.agent_chat_service.status(principal)
            if model.availability == M8AgentModelAvailability.NOT_CONFIGURED:
                raise typer.BadParameter("authority worker requires configured LIVE_ONLY Qwen")
            worker = assembly.feishu_live.agent_worker
            while True:
                worker.run_one()
                if once:
                    return
                time.sleep(interval_ms / 1_000)

        delivery = assembly.feishu_live.delivery_worker
        if delivery is None:
            raise typer.BadParameter(
                "delivery worker requires current activation, Feishu secrets, recipient, "
                "and LABCOURT_FEISHU_WORKER_TOKEN"
            )
        while True:
            delivery.run_one_cycle()
            if once:
                return
            time.sleep(interval_ms / 1_000)


__all__ = ["M8FeishuLiveComponent", "register_m8_feishu_live_commands"]
