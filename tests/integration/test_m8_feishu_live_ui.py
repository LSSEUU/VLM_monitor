from __future__ import annotations

import re
from importlib.resources import files


def test_formal_ui_exposes_runtime_workers_real_test_and_agent_channel_badge() -> None:
    package = files("labcourt.m8_ui_web")
    app = package.joinpath("app.js").read_text(encoding="utf-8")
    agent = package.joinpath("agent-chat.js").read_text(encoding="utf-8")
    agent_css = package.joinpath("agent-chat.css").read_text(encoding="utf-8")
    feishu_css = package.joinpath("feishu-live.css").read_text(encoding="utf-8")
    html = package.joinpath("app.html").read_text(encoding="utf-8")

    assert "/api/m8/integrations/feishu/runtime-status" in app
    assert "/api/m8/integrations/feishu/duty-route" in app
    assert "/api/m8/integrations/feishu/test-card-dispatches" in app
    assert 'data-action="feishu-live-test"' in app
    assert "UNKNOWN_DELIVERY" in app and "不会自动重试" in app
    assert "/channel-projection" in agent
    assert "agent-channel-badge" in agent
    assert ".agent-channel-badge" in agent_css
    assert "feishu-runtime-grid" in feishu_css
    assert "@media (max-width:700px)" in feishu_css
    assert "prefers-reduced-motion" in feishu_css
    assert "/assets/feishu-live.css" in html


def test_formal_ui_keeps_agent_feishu_and_hearing_evaluation_union() -> None:
    package = files("labcourt.m8_ui_web")
    app = package.joinpath("app.js").read_text(encoding="utf-8")
    html = package.joinpath("app.html").read_text(encoding="utf-8")

    assert "/app/evaluation" in app
    assert "/api/m8/evaluation/dashboard" in app
    assert "hearing-preparation" in app
    assert "hearing-acquisitions" in app
    assert "window.LabCourtAgentChat" in app
    assert "/query-projections" in app
    assert 'settingsSection:"messages"' in app
    assert 'role() !== "OPERATIONS"' in app
    assert "runCaseHref" in app
    for asset in (
        "/assets/app.css",
        "/assets/agent-chat.css",
        "/assets/feishu-live.css",
        "/assets/agent-chat.js",
        "/assets/app.js",
    ):
        assert asset in html
    versions = re.findall(r'[?]v=([^"\']+)', html)
    assert len(versions) == 5
    assert len(set(versions)) == 1
    assert "<<<<<<<" not in app + html
