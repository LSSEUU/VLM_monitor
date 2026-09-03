from __future__ import annotations

import subprocess
from pathlib import Path

from typer.core import TyperCommand, TyperGroup
from typer.main import get_command

from labcourt.cli import app

PROJECT_ROOT = Path(__file__).parents[2]


def test_demo_commands_and_consolidated_windows_entry_are_explicit() -> None:
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
    platform = demo.commands["platform"]
    assert isinstance(platform, TyperCommand)
    platform_options = {option for parameter in platform.params for option in parameter.opts}
    assert {"--output", "--input", "--port", "--check", "--json"} <= platform_options
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
        "ppe-notification-route",
        "ppe-notification-deliver",
        "ppe-notification-reply",
        "ppe-appeal-resolve",
        "ppe-outcome-notification-route",
        "ppe-outcome-notification-deliver",
        "ppe-outcome-notification-acknowledge",
        "student-appeal",
        "notification-route",
        "notification-deliver",
        "notification-acknowledge",
    ):
        assert isinstance(demo.commands[command_name], TyperCommand)
    media_bind = demo.commands["media-bind"]
    assert isinstance(media_bind, TyperCommand)
    media_options = {option for parameter in media_bind.params for option in parameter.opts}
    assert {"--input", "--output", "--json"} <= media_options
    student_appeal = demo.commands["student-appeal"]
    assert isinstance(student_appeal, TyperCommand)
    student_appeal_options = {
        option for parameter in student_appeal.params for option in parameter.opts
    }
    assert {"--reason", "--output", "--confirmed", "--json"} <= student_appeal_options
    ppe_reply = demo.commands["ppe-notification-reply"]
    assert isinstance(ppe_reply, TyperCommand)
    ppe_reply_options = {option for parameter in ppe_reply.params for option in parameter.opts}
    assert {"--kind", "--text", "--output", "--confirmed", "--json"} <= (ppe_reply_options)
    appeal_resolution = demo.commands["ppe-appeal-resolve"]
    assert isinstance(appeal_resolution, TyperCommand)
    resolution_options = {
        option for parameter in appeal_resolution.params for option in parameter.opts
    }
    assert {"--resolution", "--reason", "--output", "--confirmed", "--json"} <= (resolution_options)

    for name in (
        "labcourt-demo.ps1",
        "labcourt-demo-start.ps1",
        "labcourt-demo-e2e.ps1",
        "labcourt-platform-start.ps1",
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

    assert [path.name for path in PROJECT_ROOT.glob("*.cmd")] == ["labcourt.cmd"]
    launcher = (PROJECT_ROOT / "labcourt.cmd").read_text(encoding="utf-8")
    assert "scripts\\windows\\labcourt-demo.ps1" in launcher
    assert "scripts\\windows\\labcourt-demo-start.ps1" in launcher
    assert "scripts\\windows\\labcourt-demo-e2e.ps1" in launcher
    assert "scripts\\windows\\labcourt-platform-start.ps1" in launcher
