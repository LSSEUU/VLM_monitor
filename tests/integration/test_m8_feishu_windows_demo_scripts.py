from __future__ import annotations

import json
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).parents[2]
LOCAL_CONFIG = PROJECT_ROOT / ".labcourt-local" / "feishu-secrets.json"
BLANK_EXAMPLE = PROJECT_ROOT / ".labcourt-local" / "feishu-secrets.example.json"
WINDOWS_SCRIPTS = PROJECT_ROOT / "scripts" / "windows"


def test_real_local_config_is_ignored_and_only_example_is_blank() -> None:
    ignored = subprocess.run(
        ["git", "check-ignore", "--quiet", "--", str(LOCAL_CONFIG)],
        cwd=PROJECT_ROOT,
        check=False,
    )
    example_ignored = subprocess.run(
        ["git", "check-ignore", "--quiet", "--", str(BLANK_EXAMPLE)],
        cwd=PROJECT_ROOT,
        check=False,
    )

    assert ignored.returncode == 0
    assert example_ignored.returncode == 1
    payload = json.loads(BLANK_EXAMPLE.read_text(encoding="utf-8"))
    assert set(payload["credentials"].values()) == {""}
    assert payload["personal_demo_only"] is True
    assert payload["default_preflight_required"] is True
    assert payload["automatic_send_permitted"] is False
    assert payload["production_ready"] is False


def test_network_capable_entrypoints_run_preflight_before_action() -> None:
    webhook = (WINDOWS_SCRIPTS / "feishu-webhook.ps1").read_text(encoding="utf-8")
    send_one = (WINDOWS_SCRIPTS / "feishu-send-one.ps1").read_text(encoding="utf-8")

    assert webhook.index("feishu-preflight.ps1") < webhook.index(
        '"feishu", "webhook-serve"'
    )
    assert send_one.index("feishu-preflight.ps1") < send_one.index(
        '"feishu", "outbox-run-one"'
    )
    assert send_one.index('Read-Host "Preflight passed.') < send_one.index(
        '"feishu", "outbox-run-one"'
    )
    assert '$confirmation -cne "SEND"' in send_one
    assert "ConfirmSend" not in send_one


def test_preflight_uses_check_modes_and_never_passes_secret_values_as_arguments() -> None:
    preflight = (WINDOWS_SCRIPTS / "feishu-preflight.ps1").read_text(
        encoding="utf-8"
    )

    assert preflight.count('"--check"') == 2
    assert '"--app-id-env", $config.environment_names.app_id' in preflight
    assert '"--app-secret-env", $config.environment_names.app_secret' in preflight
    assert '"--receive-id-env", $config.environment_names.test_open_id' in preflight
    assert '"--encrypt-key-env", $config.environment_names.encrypt_key' in preflight
    assert "$config.credentials.app_secret" not in preflight
    assert "$config.credentials.encrypt_key" not in preflight


def test_all_windows_scripts_parse_without_execution() -> None:
    command = r"""
$parseErrors = @()
Get-ChildItem scripts/windows/feishu-*.ps1 | ForEach-Object {
    $tokens = $null
    $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile(
        $_.FullName, [ref]$tokens, [ref]$errors
    ) | Out-Null
    $parseErrors += $errors
}
if ($parseErrors.Count -gt 0) { exit 1 }
"""
    parsed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command", command],
        cwd=PROJECT_ROOT,
        check=False,
    )

    assert parsed.returncode == 0
