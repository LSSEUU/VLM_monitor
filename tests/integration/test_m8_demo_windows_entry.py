from __future__ import annotations

import subprocess
from pathlib import Path

from typer.core import TyperCommand, TyperGroup
from typer.main import get_command

from labcourt.cli import app

PROJECT_ROOT = Path(__file__).parents[2]


def test_demo_bootstrap_command_and_windows_entry_are_explicit() -> None:
    root = get_command(app)
    assert isinstance(root, TyperGroup)
    demo = root.commands["demo"]
    assert isinstance(demo, TyperGroup)
    command = demo.commands["bootstrap"]
    assert isinstance(command, TyperCommand)
    options = {option for parameter in command.params for option in parameter.opts}
    assert {"--output", "--json"} <= options
    api = demo.commands["api"]
    assert isinstance(api, TyperCommand)
    api_options = {option for parameter in api.params for option in parameter.opts}
    assert {"--output", "--port", "--check", "--json"} <= api_options
    case_action = demo.commands["case-action"]
    assert isinstance(case_action, TyperCommand)
    action_options = {option for parameter in case_action.params for option in parameter.opts}
    assert {"--action", "--reason", "--target", "--output", "--confirmed", "--json"} <= (
        action_options
    )
    for command_name in (
        "camera-register",
        "media-bind",
        "ppe-case-create",
        "notification-route",
        "notification-deliver",
        "notification-acknowledge",
    ):
        assert isinstance(demo.commands[command_name], TyperCommand)
    media_bind = demo.commands["media-bind"]
    assert isinstance(media_bind, TyperCommand)
    media_options = {option for parameter in media_bind.params for option in parameter.opts}
    assert {"--input", "--output", "--json"} <= media_options

    for name in (
        "labcourt-demo-bootstrap.ps1",
        "labcourt-demo-api.ps1",
        "labcourt-demo-case-action.ps1",
        "labcourt-demo-camera.ps1",
        "labcourt-demo-ppe-case.ps1",
        "labcourt-demo-notification.ps1",
        "labcourt-demo-notification-deliver.ps1",
        "labcourt-demo-notification-acknowledge.ps1",
        "labcourt-demo-start.ps1",
    ):
        script = PROJECT_ROOT / "scripts" / "windows" / name
        parsed = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-Command",
                "$e=$null;$t=$null;"
                f"[System.Management.Automation.Language.Parser]::ParseFile('{script}',[ref]$t,[ref]$e)"
                "|Out-Null;if($e.Count){exit 1}",
            ],
            cwd=PROJECT_ROOT,
            check=False,
        )
        assert parsed.returncode == 0
