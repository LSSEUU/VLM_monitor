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

    script = PROJECT_ROOT / "scripts" / "windows" / "labcourt-demo-bootstrap.ps1"
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
