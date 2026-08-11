"""Windows-friendly command boundary for the persisted M8 personal demo."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Annotated, NoReturn

import typer

from labcourt.application.m8_personal_demo_api import assemble_m8_personal_demo_api
from labcourt.application.m8_personal_demo_bootstrap import bootstrap_m8_personal_demo
from labcourt.application.m8_personal_demo_camera import register_m8_personal_demo_camera
from labcourt.application.m8_personal_demo_case_action import (
    M8PersonalDemoCaseActionError,
    execute_m8_personal_demo_case_action,
)
from labcourt.application.m8_personal_demo_media import bind_m8_personal_demo_recorded_media
from labcourt.application.m8_personal_demo_notification import (
    acknowledge_m8_personal_demo_notification,
    deliver_m8_personal_demo_notification,
    route_m8_personal_demo_notification,
)
from labcourt.application.m8_personal_demo_ppe_case import create_m8_personal_demo_ppe_case
from labcourt.application.m8_personal_demo_ppe_notification import (
    route_m8_personal_demo_ppe_notification,
)
from labcourt.application.m8_personal_demo_student_appeal import (
    M8PersonalDemoStudentAppealError,
    execute_m8_personal_demo_student_appeal,
)
from labcourt.contracts.m8_personal_demo import (
    M8PersonalDemoNotificationReceiptV1,
    M8PersonalDemoPpeCaseReceiptV1,
    M8PersonalDemoRecordedMediaReceiptV1,
)
from labcourt.contracts.m8_personal_demo_api import (
    M8PersonalDemoCaseTarget,
    M8PersonalDemoOperatorAction,
)
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


def _write_runtime_artifact(path: Path, content: bytes) -> None:
    """Refresh a fully derived local runtime file after its authority validates."""

    if path.exists() and not path.is_file():
        raise ValueError("M8 personal demo runtime artifact path is not a file")
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(content)
    temporary.replace(path)


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
            _write_runtime_artifact(
                profile_path,
                (assembly.profile.model_dump_json(indent=2) + "\n").encode("utf-8"),
            )
            _write_runtime_artifact(
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
            _write_runtime_artifact(
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
        target: Annotated[M8PersonalDemoCaseTarget, typer.Option("--target")] = (
            M8PersonalDemoCaseTarget.EMERGENCY_SMOKE
        ),
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
            ppe_case_id = None
            bootstrap_path: Path | None = output / "bootstrap-receipt.json"
            if target == M8PersonalDemoCaseTarget.PPE_CANDIDATE:
                ppe_receipt = M8PersonalDemoPpeCaseReceiptV1.model_validate_json(
                    (output / "ppe-case-receipt.json").read_bytes()
                )
                ppe_case_id = ppe_receipt.case_id
                bootstrap_path = None
            run = execute_m8_personal_demo_case_action(
                access_path=output / "api-access.json",
                action=action,
                reason_summary=reason,
                confirmed=confirmed,
                bootstrap_receipt_path=bootstrap_path,
                target_case_id=ppe_case_id,
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
            "target": target.value,
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

    @demo.command("camera-register")
    def camera_register(
        output: Annotated[Path, typer.Option("--output", file_okay=False)] = Path(
            ".labcourt-local/labcourt-demo"
        ),
        json_output: Annotated[bool, typer.Option("--json")] = False,
    ) -> None:
        try:
            output.mkdir(parents=True, exist_ok=True)
            receipt = register_m8_personal_demo_camera(output / "labcourt.sqlite3")
            receipt_path = output / "camera-registration-receipt.json"
            _write_exact(
                receipt_path,
                (receipt.model_dump_json(indent=2) + "\n").encode("utf-8"),
            )
        except (LabCourtError, OSError, TypeError, ValueError, sqlite3.DatabaseError) as error:
            _fail(error)
        summary: dict[str, object] = {
            "camera_count": receipt.camera_count,
            "display_badge": receipt.display_badge,
            "gpu_used": receipt.gpu_used,
            "life_safety_eligible": receipt.life_safety_eligible,
            "live_camera_claim_permitted": receipt.live_camera_claim_permitted,
            "media_attached": receipt.media_attached,
            "mode": receipt.mode.value,
            "network_used": receipt.network_used,
            "source_count": receipt.source_count,
            "source_id": receipt.source_id,
        }
        if json_output:
            typer.echo(json.dumps(summary, ensure_ascii=False, sort_keys=True))
        else:
            typer.echo(
                "LabCourt PERSONAL DEMO camera registered: "
                "SIMULATED RECORDED VIDEO; no media is attached yet"
            )

    @demo.command("media-bind")
    def media_bind(
        input_media: Annotated[Path, typer.Option("--input", dir_okay=False)],
        output: Annotated[Path, typer.Option("--output", file_okay=False)] = Path(
            ".labcourt-local/labcourt-demo"
        ),
        json_output: Annotated[bool, typer.Option("--json")] = False,
    ) -> None:
        try:
            output.mkdir(parents=True, exist_ok=True)
            receipt = bind_m8_personal_demo_recorded_media(
                output / "labcourt.sqlite3",
                input_media,
                output,
            )
            receipt_path = output / "camera-media-receipt.json"
            _write_exact(
                receipt_path,
                (receipt.model_dump_json(indent=2) + "\n").encode("utf-8"),
            )
        except (LabCourtError, OSError, TypeError, ValueError, sqlite3.DatabaseError) as error:
            _fail(error)
        summary: dict[str, object] = {
            "display_badge": receipt.display_badge,
            "exact_byte_copy": receipt.exact_byte_copy,
            "gpu_used": receipt.gpu_used,
            "input_file_sha256": receipt.input_file_sha256,
            "media_attached": receipt.media_attached,
            "network_used": receipt.network_used,
            "original_media_modified": receipt.original_media_modified,
            "playback_media_ref": receipt.playback_media_ref,
            "source_id": receipt.source_id,
        }
        if json_output:
            typer.echo(json.dumps(summary, ensure_ascii=False, sort_keys=True))
        else:
            typer.echo(
                "LabCourt PERSONAL DEMO media attached: "
                "SIMULATED RECORDED VIDEO; exact local byte copy"
            )

    @demo.command("ppe-case-create")
    def ppe_case_create(
        output: Annotated[Path, typer.Option("--output", file_okay=False)] = Path(
            ".labcourt-local/labcourt-demo"
        ),
        json_output: Annotated[bool, typer.Option("--json")] = False,
    ) -> None:
        try:
            media_receipt = M8PersonalDemoRecordedMediaReceiptV1.model_validate_json(
                (output / "camera-media-receipt.json").read_bytes()
            )
            receipt = create_m8_personal_demo_ppe_case(
                output / "labcourt.sqlite3",
                output,
                media_receipt,
            )
            _write_exact(
                output / "ppe-case-receipt.json",
                (receipt.model_dump_json(indent=2) + "\n").encode("utf-8"),
            )
        except (LabCourtError, OSError, TypeError, ValueError, sqlite3.DatabaseError) as error:
            _fail(error)
        summary: dict[str, object] = {
            "candidate_kind": receipt.candidate_kind,
            "case_id": receipt.case_id,
            "case_status": receipt.case_status.value,
            "display_badge": receipt.display_badge,
            "human_verification_required": receipt.human_verification_required,
            "machine_weak_label_is_ground_truth": receipt.machine_weak_label_is_ground_truth,
            "risk_level": receipt.risk_level.value,
            "subject_actor_id": receipt.subject_actor_id,
        }
        if json_output:
            typer.echo(json.dumps(summary, ensure_ascii=False, sort_keys=True))
        else:
            typer.echo(
                "LabCourt PERSONAL DEMO PPE candidate created: "
                "SIMULATED MACHINE WEAK LABEL; pending human verification"
            )

    @demo.command("student-appeal")
    def student_appeal(
        reason: Annotated[str, typer.Option("--reason", min=1, max=2048)],
        output: Annotated[Path, typer.Option("--output", file_okay=False)] = Path(
            ".labcourt-local/labcourt-demo"
        ),
        confirmed: Annotated[
            bool,
            typer.Option("--confirmed", help="Explicit student confirmation for one appeal."),
        ] = False,
        json_output: Annotated[bool, typer.Option("--json")] = False,
    ) -> None:
        try:
            run = execute_m8_personal_demo_student_appeal(
                access_path=output / "api-access.json",
                ppe_case_receipt_path=output / "ppe-case-receipt.json",
                reason_summary=reason,
                confirmed=confirmed,
            )
            appeal_directory = output / "student-appeals"
            appeal_directory.mkdir(parents=True, exist_ok=True)
            _write_exact(
                appeal_directory / f"{run.receipt.commit_receipt_id}.json",
                (run.receipt.model_dump_json(indent=2) + "\n").encode("utf-8"),
            )
        except (
            LabCourtError,
            M8PersonalDemoStudentAppealError,
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
            "explicit_human_confirmation": run.request.explicit_human_confirmation,
            "reason_code": run.request.reason_code.value,
            "status": run.receipt.status.value,
            "student_controlled": True,
        }
        if json_output:
            typer.echo(json.dumps(summary, ensure_ascii=False, sort_keys=True))
        else:
            typer.echo("LabCourt PERSONAL DEMO student appeal committed: APPEALED")

    @demo.command("ppe-notification-route")
    def ppe_notification_route(
        output: Annotated[Path, typer.Option("--output", file_okay=False)] = Path(
            ".labcourt-local/labcourt-demo"
        ),
        json_output: Annotated[bool, typer.Option("--json")] = False,
    ) -> None:
        try:
            ppe = M8PersonalDemoPpeCaseReceiptV1.model_validate_json(
                (output / "ppe-case-receipt.json").read_bytes()
            )
            run = route_m8_personal_demo_ppe_notification(
                output / "labcourt.sqlite3",
                ppe,
            )
            _write_exact(
                output / "ppe-notification-route-receipt.json",
                (run.receipt.model_dump_json(indent=2) + "\n").encode("utf-8"),
            )
            _write_exact(
                output / "ppe-student-card.json",
                (run.card.model_dump_json(indent=2) + "\n").encode("utf-8"),
            )
        except (LabCourtError, OSError, TypeError, ValueError, sqlite3.DatabaseError) as error:
            _fail(error)
        summary: dict[str, object] = {
            "available_actions": [action.value for action in run.card.available_actions],
            "case_id": run.receipt.case_id,
            "display_badge": run.receipt.display_badge,
            "notification_id": run.receipt.notification_id,
            "notification_status": run.receipt.notification_status.value,
            "student_actor_id": run.receipt.target_actor_id,
        }
        if json_output:
            typer.echo(json.dumps(summary, ensure_ascii=False, sort_keys=True))
        else:
            typer.echo(
                "LabCourt PERSONAL DEMO student notification queued: "
                "SIMULATED LOCAL MESSAGE CARD"
            )


__all__ = ["register_m8_demo_commands"]
