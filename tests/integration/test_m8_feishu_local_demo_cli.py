from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from labcourt.cli import app
from tests.contract.test_m8_feishu_local_demo_contracts import _payload

RUNNER = CliRunner()


def test_local_config_check_reports_only_redacted_state(tmp_path: Path) -> None:
    config_path = tmp_path / "feishu-secrets.json"
    payload = _payload()
    config_path.write_text(json.dumps(payload), encoding="utf-8")

    result = RUNNER.invoke(
        app,
        ["feishu", "local-config-check", "--config", str(config_path), "--json"],
    )

    assert result.exit_code == 0
    summary = json.loads(result.stdout)
    assert summary["credentials_present"] is True
    assert summary["default_preflight_required"] is True
    assert summary["production_ready"] is False
    credentials = payload["credentials"]
    assert isinstance(credentials, dict)
    assert all(str(value) not in result.stdout for value in credentials.values())


def test_local_config_error_never_echoes_rejected_secret(tmp_path: Path) -> None:
    config_path = tmp_path / "feishu-secrets.json"
    payload = _payload()
    credentials = payload["credentials"]
    assert isinstance(credentials, dict)
    rejected = "DO-NOT-ECHO secret"
    credentials["app_secret"] = rejected
    config_path.write_text(json.dumps(payload), encoding="utf-8")

    result = RUNNER.invoke(
        app,
        ["feishu", "local-config-check", "--config", str(config_path)],
    )

    assert result.exit_code == 2
    assert rejected not in result.stdout


def test_personal_demo_card_check_is_offline_with_minimal_credentials(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "feishu-secrets.json"
    payload = _payload()
    credentials = payload["credentials"]
    assert isinstance(credentials, dict)
    credentials["encrypt_key"] = None
    credentials["verification_token"] = None
    payload["runtime"] = None
    payload["outbox_activation"] = None
    payload["webhook_activation"] = None
    config_path.write_text(json.dumps(payload), encoding="utf-8")

    result = RUNNER.invoke(
        app,
        ["feishu", "demo-card", "--check", "--config", str(config_path), "--json"],
    )

    assert result.exit_code == 0
    summary = json.loads(result.stdout)
    assert summary["outcome"] == "CHECKED"
    assert summary["token_call_attempted"] is False
    assert summary["message_call_attempted"] is False
