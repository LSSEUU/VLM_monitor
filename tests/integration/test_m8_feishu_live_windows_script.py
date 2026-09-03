from __future__ import annotations

from pathlib import Path


def test_live_start_script_imports_user_secrets_and_hides_worker_windows() -> None:
    script = (
        Path(__file__).parents[2] / "scripts" / "windows" / "labcourt-feishu-live-start.ps1"
    ).read_text(encoding="utf-8")
    for variable in (
        "LABCOURT_FEISHU_APP_ID",
        "LABCOURT_FEISHU_APP_SECRET",
        "LABCOURT_FEISHU_TEST_OPEN_ID",
        "LABCOURT_FEISHU_WORKER_TOKEN",
        "LABCOURT_QWEN_ENDPOINT",
        "LABCOURT_QWEN_API_KEY",
    ):
        assert f'"{variable}"' in script
    assert 'GetEnvironmentVariable($name, "User")' in script
    assert "-WindowStyle Hidden" in script
    assert '"live-supervise"' in script
    assert '"live-run"' not in script
    assert "APP_SECRET=" not in script


def test_platform_start_imports_feishu_configuration_and_owns_supervisor() -> None:
    script = (
        Path(__file__).parents[2] / "scripts" / "windows" / "labcourt-platform-start.ps1"
    ).read_text(encoding="utf-8")
    for variable in (
        "LABCOURT_FEISHU_APP_ID",
        "LABCOURT_FEISHU_APP_SECRET",
        "LABCOURT_FEISHU_TEST_OPEN_ID",
        "LABCOURT_FEISHU_WORKER_TOKEN",
    ):
        assert f'"{variable}"' in script
    assert '"live-supervise"' in script
    assert "Stop-Process" in script
    assert "APP_SECRET=" not in script
