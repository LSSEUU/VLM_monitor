"""Windows-friendly command boundary for the persisted M8 personal demo."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Annotated, NoReturn

import typer

from labcourt.application.m8_personal_demo_api import assemble_m8_personal_demo_api
from labcourt.application.m8_personal_demo_bootstrap import bootstrap_m8_personal_demo
from labcourt.application.m8_personal_demo_case_action import (
    M8PersonalDemoCaseActionError,
    execute_m8_personal_demo_case_action,
)
from labcourt.application.m8_personal_demo_notification import (
    acknowledge_m8_personal_demo_notification,
    deliver_m8_personal_demo_notification,
    route_m8_personal_demo_notification,
)
from labcourt.contracts.m8_personal_demo import M8PersonalDemoNotificationReceiptV1
from labcourt.contracts.m8_personal_demo_api import M8PersonalDemoOperatorAction
from labcourt.exceptions import LabCourtError


def _fail(error: Exception) -> NoReturn:
    typer.echo(f"M8 personal demo bootstrap failed: {type(error).__name__}", err=True)
    raise typer.Exit(code=2)


def _write_exact(path: Path, content: bytes) -> None:
    if path.exists():
        if not path.is_file() or path.read_bytes() != content:
            raise ValueError("M8 personal demo artifact conflicts with the persisted authority")
        return
    path.write_bytes(content)


def register_m8_demo_commands(root: typer.Typer) -> None:
    demo = typer.Typer(help="Reproducible offline M8 campus-operations product demo.")
    root.add_typer(demo, name="demo")

    @demo.command("bootstrap")
    def bootstrap(
        output: Annotated[Path, typer.Option("--output", file_okay=False)] = Path(
            ".labcourt-local/labcourt-demo"
        ),
        json_output: Annotated[bool, typer.Option("--json")] = False,
    ) -> None:
        assembly = None
        try:
            output.mkdir(parents=True, exist_ok=True)
            database = output / "labcourt.sqlite3"
            run = bootstrap_m8_personal_demo(database)
            receipt_path = output / "bootstrap-receipt.json"
            projection_path = output / "operations-projection.json"
            _write_exact(
                receipt_path,
                (run.receipt.model_dump_json(indent=2) + "\n").encode("utf-8"),
            )
            _write_exact(
                projection_path,
                (run.projection.model_dump_json(indent=2) + "\n").encode("utf-8"),
            )
        except (LabCourtError, OSError, TypeError, ValueError, sqlite3.DatabaseError) as error:
            if assembly is not None:
                assembly.server.server_close()
            _fail(error)
        summary: dict[str, object] = {
            "bootstrap_receipt_id": run.receipt.bootstrap_receipt_id,
            "campus_id": run.receipt.campus_id,
            "case_id": run.receipt.case_id,
            "case_status": run.receipt.case_status.value,
            "database": str(database.resolve()),
            "display_badge": run.receipt.display_badge,
            "operations_projection_id": run.receipt.operations_projection_id,
            "pending_verification_case_count": (run.receipt.pending_verification_case_count),
            "projection": str(projection_path.resolve()),
            "risk_level": run.receipt.risk_level.value,
            "simulated": run.receipt.simulated,
        }
        if json_output:
            typer.echo(json.dumps(summary, ensure_ascii=False, sort_keys=True))
        else:
            typer.echo(
                "LabCourt PERSONAL DEMO initialized: "
                "SIMULATED EMERGENCY case is PENDING_VERIFICATION"
            )

    @demo.command("api")
    def api(
        output: Annotated[Path, typer.Option("--output", file_okay=False)] = Path(
            ".labcourt-local/labcourt-demo"
        ),
        port: Annotated[int, typer.Option("--port", min=1, max=65_535)] = 8877,
        check: Annotated[
            bool,
            typer.Option("--check", help="Bind, validate, write access, then close."),
        ] = False,
        json_output: Annotated[bool, typer.Option("--json")] = False,
    ) -> None:
        try:
            output.mkdir(parents=True, exist_ok=True)
            assembly = assemble_m8_personal_demo_api(output / "labcourt.sqlite3", port)
            profile_path = output / "api-profile.json"
            access_path = output / "api-access.json"
            knowledge_path = output / "knowledge-receipt.json"
            _write_exact(
                profile_path,
                (assembly.profile.model_dump_json(indent=2) + "\n").encode("utf-8"),
            )
            _write_exact(
                access_path,
                (
                    json.dumps(
                        assembly.local_access_document(),
                        ensure_ascii=False,
                        indent=2,
                        sort_keys=True,
                    )
                    + "\n"
                ).encode("utf-8"),
            )
            _write_exact(
                knowledge_path,
                (assembly.knowledge_receipt.model_dump_json(indent=2) + "\n").encode("utf-8"),
            )
        except (LabCourtError, OSError, TypeError, ValueError, sqlite3.DatabaseError) as error:
            _fail(error)
        summary: dict[str, object] = {
            "access_file": str(access_path.resolve()),
            "api_profile_id": assembly.profile.api_profile_id,
            "base_url": assembly.profile.base_url,
            "check_only": check,
            "knowledge_catalog_id": assembly.knowledge_receipt.catalog_id,
            "personal_demo_only": assembly.profile.personal_demo_only,
            "production_ready": assembly.profile.production_ready,
        }
        if check:
            assembly.server.server_close()
            if json_output:
                typer.echo(json.dumps(summary, ensure_ascii=False, sort_keys=True))
            else:
                typer.echo("LabCourt PERSONAL DEMO API check passed; server was closed")
            return
        if json_output:
            typer.echo(json.dumps(summary, ensure_ascii=False, sort_keys=True))
        else:
            typer.echo(
                f"LabCourt PERSONAL DEMO API listening at {assembly.profile.base_url}; "
                "role tokens are in the ignored api-access.json"
            )
        try:
            assembly.server.serve_forever()
        finally:
            assembly.server.server_close()

    @demo.command("case-action")
    def case_action(
        action: Annotated[M8PersonalDemoOperatorAction, typer.Option("--action")],
        reason: Annotated[str, typer.Option("--reason", min=1, max=2048)],
        output: Annotated[Path, typer.Option("--output", file_okay=False)] = Path(
            ".labcourt-local/labcourt-demo"
        ),
        confirmed: Annotated[
            bool,
            typer.Option("--confirmed", help="Explicit human confirmation for one action."),
        ] = False,
        json_output: Annotated[bool, typer.Option("--json")] = False,
    ) -> None:
        try:
            run = execute_m8_personal_demo_case_action(
                access_path=output / "api-access.json",
                bootstrap_receipt_path=output / "bootstrap-receipt.json",
                action=action,
                reason_summary=reason,
                confirmed=confirmed,
            )
            action_directory = output / "case-actions"
            action_directory.mkdir(parents=True, exist_ok=True)
            receipt_path = action_directory / f"{run.receipt.commit_receipt_id}.json"
            _write_exact(
                receipt_path,
                (run.receipt.model_dump_json(indent=2) + "\n").encode("utf-8"),
            )
        except (
            LabCourtError,
            M8PersonalDemoCaseActionError,
            OSError,
            TypeError,
            ValueError,
            sqlite3.DatabaseError,
        ) as error:
            _fail(error)
        summary: dict[str, object] = {
            "action": run.request.action.value,
            "case_id": run.receipt.case_id,
            "case_version": run.receipt.case_version,
            "commit_receipt_id": run.receipt.commit_receipt_id,
            "explicit_human_confirmation": run.request.explicit_human_confirmation,
            "status": run.receipt.status.value,
        }
        if json_output:
            typer.echo(json.dumps(summary, ensure_ascii=False, sort_keys=True))
        else:
            typer.echo(
                f"LabCourt PERSONAL DEMO Case action committed: "
                f"{run.request.action.value} -> {run.receipt.status.value}"
            )

    @demo.command("notification-route")
    def notification_route(
        output: Annotated[Path, typer.Option("--output", file_okay=False)] = Path(
            ".labcourt-local/labcourt-demo"
        ),
        json_output: Annotated[bool, typer.Option("--json")] = False,
    ) -> None:
        try:
            output.mkdir(parents=True, exist_ok=True)
            run = route_m8_personal_demo_notification(output / "labcourt.sqlite3")
            receipt_path = output / "notification-route-receipt.json"
            card_path = output / "notification-card.json"
            _write_exact(
                receipt_path,
                (run.receipt.model_dump_json(indent=2) + "\n").encode("utf-8"),
            )
            _write_exact(
                card_path,
                (run.card.model_dump_json(indent=2) + "\n").encode("utf-8"),
            )
        except (LabCourtError, OSError, TypeError, ValueError, sqlite3.DatabaseError) as error:
            _fail(error)
        summary: dict[str, object] = {
            "audience": run.receipt.audience.value,
            "card": str(card_path.resolve()),
            "case_id": run.receipt.case_id,
            "channel": run.receipt.channel.value,
            "network_used": run.receipt.network_used,
            "notification_id": run.receipt.notification_id,
            "notification_status": run.receipt.notification_status.value,
            "real_delivery_confirmed": run.receipt.real_delivery_confirmed,
            "simulated": run.receipt.simulated,
            "target_actor_id": run.receipt.target_actor_id,
        }
        if json_output:
            typer.echo(json.dumps(summary, ensure_ascii=False, sort_keys=True))
        else:
            typer.echo(
                "LabCourt PERSONAL DEMO notification routed: "
                "SIMULATED emergency card is QUEUED for the safety officer"
            )

    @demo.command("notification-deliver")
    def notification_deliver(
        output: Annotated[Path, typer.Option("--output", file_okay=False)] = Path(
            ".labcourt-local/labcourt-demo"
        ),
        json_output: Annotated[bool, typer.Option("--json")] = False,
    ) -> None:
        try:
            route_path = output / "notification-route-receipt.json"
            route_receipt = M8PersonalDemoNotificationReceiptV1.model_validate_json(
                route_path.read_bytes()
            )
            receipt = deliver_m8_personal_demo_notification(
                output / "labcourt.sqlite3",
                route_receipt,
            )
            receipt_path = output / "notification-delivery-receipt.json"
            _write_exact(
                receipt_path,
                (receipt.model_dump_json(indent=2) + "\n").encode("utf-8"),
            )
        except (LabCourtError, OSError, TypeError, ValueError, sqlite3.DatabaseError) as error:
            _fail(error)
        transition = receipt.audit_event.transition_command
        delivery = transition.delivery_receipt if transition is not None else None
        summary: dict[str, object] = {
            "case_transition_permitted": False,
            "channel": receipt.audit_event.notification_authority.plan.target.channel.value,
            "network_used": False,
            "notification_id": receipt.notification_id,
            "notification_status": receipt.status.value,
            "notification_version": receipt.notification_version,
            "real_delivery_confirmed": False,
            "simulated": delivery.simulated if delivery is not None else True,
        }
        if json_output:
            typer.echo(json.dumps(summary, ensure_ascii=False, sort_keys=True))
        else:
            typer.echo(
                "LabCourt PERSONAL DEMO notification delivered by the offline fake: "
                "SIMULATED only; real delivery remains unconfirmed"
            )

    @demo.command("notification-acknowledge")
    def notification_acknowledge(
        output: Annotated[Path, typer.Option("--output", file_okay=False)] = Path(
            ".labcourt-local/labcourt-demo"
        ),
        confirmed: Annotated[
            bool,
            typer.Option("--confirmed", help="Explicit safety-officer acknowledgement."),
        ] = False,
        json_output: Annotated[bool, typer.Option("--json")] = False,
    ) -> None:
        try:
            route_path = output / "notification-route-receipt.json"
            route_receipt = M8PersonalDemoNotificationReceiptV1.model_validate_json(
                route_path.read_bytes()
            )
            receipt = acknowledge_m8_personal_demo_notification(
                output / "labcourt.sqlite3",
                route_receipt,
                confirmed=confirmed,
            )
            receipt_path = output / "notification-acknowledgement-receipt.json"
            _write_exact(
                receipt_path,
                (receipt.model_dump_json(indent=2) + "\n").encode("utf-8"),
            )
        except (LabCourtError, OSError, TypeError, ValueError, sqlite3.DatabaseError) as error:
            _fail(error)
        transition = receipt.audit_event.transition_command
        summary: dict[str, object] = {
            "actor_id": (
                transition.actor_authority.actor_id
                if transition is not None and transition.actor_authority is not None
                else None
            ),
            "case_transition_permitted": False,
            "explicit_human_confirmation": (
                transition.explicit_human_confirmation if transition is not None else False
            ),
            "notification_id": receipt.notification_id,
            "notification_status": receipt.status.value,
            "notification_version": receipt.notification_version,
        }
        if json_output:
            typer.echo(json.dumps(summary, ensure_ascii=False, sort_keys=True))
        else:
            typer.echo(
                "LabCourt PERSONAL DEMO notification acknowledged by the safety officer; "
                "the Case was not changed"
            )


__all__ = ["register_m8_demo_commands"]
