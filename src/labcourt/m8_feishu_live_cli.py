"""Explicit live Feishu worker commands for the campus platform."""

from __future__ import annotations

import os
import sys
import time
from collections.abc import Callable
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
from labcourt.services.m8_feishu_process_supervisor import (
    M8FeishuLiveProcessSupervisor,
    M8FeishuSupervisorAlreadyRunning,
    M8FeishuSupervisorLock,
    build_feishu_component_starter,
)


class M8FeishuLiveComponent(StrEnum):
    LONG_CONNECTION = "LONG_CONNECTION"
    AUTHORITY_WORKER = "AUTHORITY_WORKER"
    DELIVERY_WORKER = "DELIVERY_WORKER"


def _run_resilient_worker(
    run_cycle: Callable[[], object],
    *,
    on_failure: Callable[[], None],
    once: bool,
    interval_seconds: float,
    sleep: Callable[[float], None] = time.sleep,
    stop_requested: Callable[[], bool] = lambda: False,
) -> None:
    delay = interval_seconds
    while not stop_requested():
        try:
            run_cycle()
        except Exception:
            if once:
                raise
            on_failure()
            if stop_requested():
                return
            sleep(delay)
            delay = min(delay * 2, 10.0)
            continue
        delay = interval_seconds
        if once or stop_requested():
            return
        sleep(interval_seconds)


def _live_assembly(output: Path, input_media: Path):  # type: ignore[no-untyped-def]
    assembly = assemble_m8_platform_demo_api(
        project_root=Path(__file__).parents[2],
        database_path=output / PLATFORM_DATABASE_NAME,
        input_media_path=input_media,
        port=0,
    )
    assembly.server.server_close()
    operations_token = M8_PLATFORM_ROLE_TOKENS[M8ActorRole.OPERATIONS]
    principal = assembly.server.api_authenticator.authenticate(f"Bearer {operations_token}")
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
    return assembly, principal


def _record_authority_failure(worker: object) -> None:
    try:
        worker.record_runtime_failure()  # type: ignore[attr-defined]
    except Exception:
        typer.echo(
            "Feishu authority worker cycle failed; runtime receipt was temporarily "
            "unavailable; retrying.",
            err=True,
        )
    else:
        typer.echo(
            "Feishu authority worker cycle failed; typed failure recorded; retrying.",
            err=True,
        )


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
        assembly, principal = _live_assembly(output, input_media)

        if component == M8FeishuLiveComponent.LONG_CONNECTION:
            app_id = os.environ.get("LABCOURT_FEISHU_APP_ID", "")
            app_secret = os.environ.get("LABCOURT_FEISHU_APP_SECRET", "")

            def run_connection() -> None:
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
                raise RuntimeError("Feishu long connection exited unexpectedly")

            _run_resilient_worker(
                run_connection,
                on_failure=lambda: typer.echo(
                    "Feishu long connection stopped; rebuilding client and retrying.",
                    err=True,
                ),
                once=False,
                interval_seconds=interval_ms / 1_000,
            )
            return

        if component == M8FeishuLiveComponent.AUTHORITY_WORKER:
            model = assembly.server.agent_chat_service.status(principal)
            if model.availability == M8AgentModelAvailability.NOT_CONFIGURED:
                raise typer.BadParameter("authority worker requires configured LIVE_ONLY Qwen")
            worker = assembly.feishu_live.agent_worker
            _run_resilient_worker(
                worker.run_one,
                on_failure=lambda: _record_authority_failure(worker),
                once=once,
                interval_seconds=interval_ms / 1_000,
            )
            return

        delivery = assembly.feishu_live.delivery_worker
        if delivery is None:
            raise typer.BadParameter(
                "delivery worker requires current activation, Feishu secrets, recipient, "
                "and LABCOURT_FEISHU_WORKER_TOKEN"
            )
        _run_resilient_worker(
            delivery.run_one_cycle,
            on_failure=lambda: typer.echo(
                "Feishu delivery worker cycle failed; typed failure recorded; retrying.",
                err=True,
            ),
            once=once,
            interval_seconds=interval_ms / 1_000,
        )

    @feishu.command("live-supervise")
    def live_supervise(
        output: Annotated[Path, typer.Option("--output", file_okay=False)] = Path(
            ".labcourt-local/labcourt-platform-demo"
        ),
        input_media: Annotated[
            Path,
            typer.Option("--input", exists=True, dir_okay=False),
        ] = Path("inputs/goggles-missing.mp4"),
        interval_ms: Annotated[
            int,
            typer.Option("--interval-ms", min=100, max=10_000),
        ] = 500,
        check: Annotated[bool, typer.Option("--check")] = False,
        stop_file: Annotated[Path | None, typer.Option("--stop-file")] = None,
    ) -> None:
        """Validate, start, and continuously supervise all live components."""

        output.mkdir(parents=True, exist_ok=True)
        assembly, principal = _live_assembly(output, input_media)
        model = assembly.server.agent_chat_service.status(principal)
        if model.availability == M8AgentModelAvailability.NOT_CONFIGURED:
            raise typer.BadParameter("live supervisor requires configured LIVE_ONLY Qwen")
        if not os.environ.get("LABCOURT_FEISHU_APP_ID") or not os.environ.get(
            "LABCOURT_FEISHU_APP_SECRET"
        ):
            raise typer.BadParameter("live supervisor requires Feishu App credentials")
        if assembly.feishu_live.delivery_worker is None:
            raise typer.BadParameter(
                "live supervisor requires current activation, recipient, and worker token"
            )
        if check:
            typer.echo("Feishu live supervisor preflight passed")
            return

        executable = Path(sys.argv[0]).resolve()
        starter = build_feishu_component_starter(
            command_prefix=[str(executable)],
            output=output.resolve(),
            input_media=input_media.resolve(),
        )
        supervisor = M8FeishuLiveProcessSupervisor(
            start_process=starter,
            monotonic=time.monotonic,
        )
        lock = M8FeishuSupervisorLock(output / "feishu-live" / "supervisor.lock")
        try:
            lock.acquire()
        except M8FeishuSupervisorAlreadyRunning as error:
            typer.echo(str(error), err=True)
            raise typer.Exit(code=3) from None
        try:
            supervisor.start_all()
            while stop_file is None or stop_file.exists():
                time.sleep(interval_ms / 1_000)
                supervisor.poll_once()
        except KeyboardInterrupt:
            pass
        finally:
            supervisor.shutdown()
            lock.release()


__all__ = [
    "M8FeishuLiveComponent",
    "_run_resilient_worker",
    "register_m8_feishu_live_commands",
]
