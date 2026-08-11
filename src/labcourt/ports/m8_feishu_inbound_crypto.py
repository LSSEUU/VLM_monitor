"""Cryptographic primitive port for encrypted Feishu event payloads."""

from __future__ import annotations

from typing import Protocol


class M8FeishuInboundCrypto(Protocol):
    def decrypt_aes_256_cbc(
        self,
        ciphertext_with_iv: bytes,
        key_sha256: bytes,
    ) -> bytes: ...


__all__ = ["M8FeishuInboundCrypto"]
