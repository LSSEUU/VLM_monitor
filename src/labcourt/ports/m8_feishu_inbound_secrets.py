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


class M8FeishuInboundResolvedSecrets:
    """Short-lived mutable buffers whose repr never exposes inbound secrets."""

    __slots__ = (
        "_closed",
        "_encrypt_key",
        "_verification_token",
        "encrypt_key_reference_id",
        "inbound_profile_id",
        "verification_token_reference_id",
    )

    def __init__(
        self,
        *,
        inbound_profile_id: str,
        encrypt_key_reference_id: str,
        verification_token_reference_id: str,
        encrypt_key: bytes,
        verification_token: bytes,
    ) -> None:
        if not all(isinstance(item, bytes) and item for item in (encrypt_key, verification_token)):
            raise ValueError("M8 Feishu inbound resolved secrets require non-empty bytes")
        self.inbound_profile_id = inbound_profile_id
        self.encrypt_key_reference_id = encrypt_key_reference_id
        self.verification_token_reference_id = verification_token_reference_id
        self._encrypt_key = bytearray(encrypt_key)
        self._verification_token = bytearray(verification_token)
        self._closed = False

    def __repr__(self) -> str:
        return f"M8FeishuInboundResolvedSecrets(redacted=True, closed={self._closed})"

    def _read(self, value: bytearray) -> bytes:
        if self._closed:
            raise RuntimeError("M8 Feishu inbound resolved secrets lease is closed")
        return bytes(value)

    def encrypt_key_bytes(self) -> bytes:
        return self._read(self._encrypt_key)

    def verification_token_bytes(self) -> bytes:
        return self._read(self._verification_token)

    def close(self) -> None:
        for value in (self._encrypt_key, self._verification_token):
            value[:] = b"\x00" * len(value)
        self._closed = True

    def __enter__(self) -> M8FeishuInboundResolvedSecrets:
        if self._closed:
            raise RuntimeError("M8 Feishu inbound resolved secrets lease is closed")
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


class M8FeishuInboundSecretResolver(Protocol):
    def resolve(
        self,
        profile: M8FeishuInboundWebhookProfileV1,
    ) -> AbstractContextManager[M8FeishuInboundSecretLease]: ...


__all__ = [
    "M8FeishuInboundResolvedSecrets",
    "M8FeishuInboundSecretLease",
    "M8FeishuInboundSecretResolver",
]
