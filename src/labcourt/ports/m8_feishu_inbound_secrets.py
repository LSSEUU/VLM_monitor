"""Ephemeral secret resolver port for Feishu encrypted webhook verification."""

from __future__ import annotations

from contextlib import AbstractContextManager
from typing import Protocol

from labcourt.contracts.m8_feishu_inbound import M8FeishuInboundWebhookProfileV1


class M8FeishuInboundSecretLease(Protocol):
    inbound_profile_id: str
    encrypt_key_reference_id: str
    verification_token_reference_id: str

    def encrypt_key_bytes(self) -> bytes: ...

    def verification_token_bytes(self) -> bytes: ...


class M8FeishuInboundSecretResolver(Protocol):
    def resolve(
        self,
        profile: M8FeishuInboundWebhookProfileV1,
    ) -> AbstractContextManager[M8FeishuInboundSecretLease]: ...


__all__ = ["M8FeishuInboundSecretLease", "M8FeishuInboundSecretResolver"]
