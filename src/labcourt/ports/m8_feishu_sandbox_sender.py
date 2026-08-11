"""Port for one activated Feishu sandbox send attempt."""

from __future__ import annotations

from typing import Protocol

from labcourt.contracts.m8_feishu_notification import M8FeishuCardDispatchPreflightV1
from labcourt.contracts.m8_feishu_transport import M8FeishuSandboxSendReceiptV1


class M8FeishuSandboxSender(Protocol):
    def send_authorized(
        self,
        preflight: M8FeishuCardDispatchPreflightV1,
        rendered_card: bytes,
        dispatch_authorization_id: str,
    ) -> M8FeishuSandboxSendReceiptV1: ...

    def read_raw_response(self, raw_response_ref: str) -> bytes: ...


__all__ = ["M8FeishuSandboxSender"]
