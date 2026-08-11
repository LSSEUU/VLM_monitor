"""Secret-redacting validation for the ignored Windows personal-demo file."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer

from labcourt.adapters.m8_feishu_stdlib_http import StdlibM8FeishuHttpTransport
from labcourt.contracts.m8_feishu_local_demo import M8FeishuLocalDemoConfigV1
from labcourt.contracts.m8_feishu_personal_demo import (
    M8FeishuPersonalDemoOutcome,
    M8FeishuPersonalDemoProbeV1,
)
from labcourt.m8_feishu_cli_support import echo_summary, fail
from labcourt.services.m8_feishu_personal_demo import M8FeishuPersonalDemoService

_MAX_LOCAL_CONFIG_BYTES = 64 * 1024


def load_m8_feishu_local_demo_config(path: Path) -> M8FeishuLocalDemoConfigV1:
    """Load a bounded local config without ever returning plaintext in an error."""

    document = path.read_bytes()
    if not 0 < len(document) <= _MAX_LOCAL_CONFIG_BYTES:
        raise ValueError("Feishu local demo config exceeds the allowed bound")
    return M8FeishuLocalDemoConfigV1.model_validate_json(document)


def register_m8_feishu_local_demo_commands(feishu: typer.Typer) -> None:
    @feishu.command("local-config-check")
    def local_config_check(
        config: Annotated[
            Path,
            typer.Option("--config", exists=True, dir_okay=False, readable=True),
        ],
        json_output: Annotated[bool, typer.Option("--json")] = False,
    ) -> None:
        try:
            parsed = load_m8_feishu_local_demo_config(config)
        except (OSError, TypeError, ValueError) as error:
            fail("local config check", error)
        summary: dict[str, object] = {
            "authority_configured": parsed.runtime is not None,
            "automatic_send_permitted": parsed.automatic_send_permitted,
            "credentials_present": True,
            "default_preflight_required": parsed.default_preflight_required,
            "display_badge": parsed.display_badge,
            "inbound_credentials_present": (
                parsed.credentials.encrypt_key is not None
                and parsed.credentials.verification_token is not None
            ),
            "personal_demo_only": parsed.personal_demo_only,
            "production_ready": parsed.production_ready,
            "schema_version": parsed.schema_version,
        }
        echo_summary(
            summary,
            json_output,
            (
                "Feishu personal-demo local config passed; credentials are present "
                "and redacted; preflight remains required"
            ),
        )

    @feishu.command("demo-card")
    def demo_card(
        config: Annotated[
            Path,
            typer.Option("--config", exists=True, dir_okay=False, readable=True),
        ],
        output: Annotated[Path, typer.Option("--output", file_okay=False)] = Path(
            ".labcourt-local/feishu-demo-runs"
        ),
        check: Annotated[
            bool,
            typer.Option("--check", help="Validate locally without any provider call."),
        ] = False,
        confirmed: Annotated[
            bool,
            typer.Option(
                "--confirmed",
                help="Explicitly permit one static PERSONAL DEMO card attempt.",
            ),
        ] = False,
        json_output: Annotated[bool, typer.Option("--json")] = False,
    ) -> None:
        if check == confirmed:
            fail("personal demo card", ValueError("choose exactly one of --check/--confirmed"))
        try:
            parsed = load_m8_feishu_local_demo_config(config)
            app_id = parsed.credentials.app_id.get_secret_value().encode("utf-8")
            app_secret = parsed.credentials.app_secret.get_secret_value().encode("utf-8")
            open_id = parsed.credentials.test_open_id.get_secret_value().encode("utf-8")
            requested_at = datetime.now(UTC)
            probe = M8FeishuPersonalDemoProbeV1(
                app_id_sha256=hashlib.sha256(app_id).hexdigest(),
                recipient_open_id_sha256=hashlib.sha256(open_id).hexdigest(),
                requested_at=requested_at,
                probe_manifest_id=hashlib.sha256(
                    b"labcourt-m8-feishu-personal-demo-probe-v1"
                ).hexdigest(),
            )
            service = M8FeishuPersonalDemoService(
                StdlibM8FeishuHttpTransport(),
                lambda: datetime.now(UTC),
            )
            run = (
                service.check(probe, app_id, app_secret, open_id)
                if check
                else service.send(probe, app_id, app_secret, open_id)
            )
            if not check:
                run_directory = output / run.receipt.probe_receipt_id
                run_directory.mkdir(parents=True, exist_ok=False)
                for reference, raw in run.raw_artifacts:
                    (run_directory / f"{reference}.json").write_bytes(raw)
                (run_directory / "receipt.json").write_text(
                    run.receipt.model_dump_json(indent=2),
                    encoding="utf-8",
                )
        except (OSError, TypeError, ValueError) as error:
            fail("personal demo card", error)
        summary: dict[str, object] = {
            "case_transition_permitted": run.receipt.case_transition_permitted,
            "message_call_attempted": run.receipt.message_call_attempted,
            "notification_transition_permitted": (
                run.receipt.notification_transition_permitted
            ),
            "outcome": run.receipt.outcome.value,
            "probe_receipt_id": run.receipt.probe_receipt_id,
            "real_delivery_confirmed": run.receipt.real_delivery_confirmed,
            "token_call_attempted": run.receipt.token_call_attempted,
        }
        echo_summary(
            summary,
            json_output,
            (
                "Feishu PERSONAL DEMO card result: "
                f"{run.receipt.outcome.value}; real delivery remains unconfirmed"
            ),
        )
        if run.receipt.outcome not in {
            M8FeishuPersonalDemoOutcome.CHECKED,
            M8FeishuPersonalDemoOutcome.MESSAGE_ACCEPTED,
        }:
            raise typer.Exit(code=3)


__all__ = [
    "load_m8_feishu_local_demo_config",
    "register_m8_feishu_local_demo_commands",
]
