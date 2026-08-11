"""Secret-redacting validation for the ignored Windows personal-demo file."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from labcourt.contracts.m8_feishu_local_demo import M8FeishuLocalDemoConfigV1
from labcourt.m8_feishu_cli_support import echo_summary, fail

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
            "automatic_send_permitted": parsed.automatic_send_permitted,
            "credentials_present": True,
            "default_preflight_required": parsed.default_preflight_required,
            "display_badge": parsed.display_badge,
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


__all__ = [
    "load_m8_feishu_local_demo_config",
    "register_m8_feishu_local_demo_commands",
]
