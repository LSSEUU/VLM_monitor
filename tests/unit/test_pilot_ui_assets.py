from __future__ import annotations

from importlib.resources import files


def test_pilot_ui_assets_are_offline_csp_compatible_and_cover_the_mvp() -> None:
    root = files("labcourt.pilot_ui_web")
    html = root.joinpath("index.html").read_text(encoding="utf-8")
    css = root.joinpath("app.css").read_text(encoding="utf-8")

    for identifier in (
        "video-select",
        "stage-list",
        "video-player",
        "timeline",
        "case-detail",
        "alert-list",
    ):
        assert f'id="{identifier}"' in html
    assert "https://" not in html
    assert "<style" not in html
    assert "onclick=" not in html
    assert "prefers-reduced-motion" in css
    assert "min-height: 44px" in css
