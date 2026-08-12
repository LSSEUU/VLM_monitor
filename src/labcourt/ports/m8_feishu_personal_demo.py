"""One-shot HTTP port for the isolated Feishu personal-demo probe."""

from __future__ import annotations

from typing import Protocol

from labcourt.ports.m8_feishu_http import M8FeishuHttpResponse


class M8FeishuPersonalDemoHttpTransport(Protocol):
    def acquire_personal_demo_token(
        self,
        app_id: bytes,
        app_secret: bytes,
        timeout_ms: int,
    ) -> M8FeishuHttpResponse: ...

    def send_personal_demo_card(
        self,
        open_id: bytes,
        tenant_access_token: bytes,
        provider_uuid: str,
        rendered_card: bytes,
        timeout_ms: int,
    ) -> M8FeishuHttpResponse: ...


__all__ = ["M8FeishuPersonalDemoHttpTransport"]
