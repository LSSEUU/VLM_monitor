"""Ephemeral, non-serializable Feishu secret resolution boundary."""

from __future__ import annotations

from contextlib import AbstractContextManager
from typing import Protocol

from labcourt.contracts.m8_feishu_notification import (
    M8FeishuAdapterProfileV1,
    M8FeishuRecipientBindingAuthorityV1,
)


class M8FeishuResolvedSecrets:
    """Short-lived mutable buffers whose repr never exposes secret values."""

    __slots__ = (
        "_app_id",
        "_app_secret",
        "_closed",
        "_open_id",
        "binding_authority_id",
        "credential_bundle_reference_id",
        "profile_id",
    )

    def __init__(
        self,
        *,
        profile_id: str,
        binding_authority_id: str,
        credential_bundle_reference_id: str,
        app_id: bytes,
        app_secret: bytes,
        open_id: bytes,
    ) -> None:
        if not all(isinstance(item, bytes) and item for item in (app_id, app_secret, open_id)):
            raise ValueError("M8 Feishu resolved secrets require non-empty bytes")
        self.profile_id = profile_id
        self.binding_authority_id = binding_authority_id
        self.credential_bundle_reference_id = credential_bundle_reference_id
        self._app_id = bytearray(app_id)
        self._app_secret = bytearray(app_secret)
        self._open_id = bytearray(open_id)
        self._closed = False

    def __repr__(self) -> str:
        return f"M8FeishuResolvedSecrets(redacted=True, closed={self._closed})"

    def _read(self, value: bytearray) -> bytes:
        if self._closed:
            raise RuntimeError("M8 Feishu resolved secrets lease is closed")
        return bytes(value)

    def app_id_bytes(self) -> bytes:
        return self._read(self._app_id)

    def app_secret_bytes(self) -> bytes:
        return self._read(self._app_secret)

    def open_id_bytes(self) -> bytes:
        return self._read(self._open_id)

    def close(self) -> None:
        for value in (self._app_id, self._app_secret, self._open_id):
            value[:] = b"\x00" * len(value)
        self._closed = True

    def __enter__(self) -> M8FeishuResolvedSecrets:
        if self._closed:
            raise RuntimeError("M8 Feishu resolved secrets lease is closed")
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


class M8FeishuSecretResolver(Protocol):
    def resolve(
        self,
        profile: M8FeishuAdapterProfileV1,
        recipient_binding: M8FeishuRecipientBindingAuthorityV1,
    ) -> AbstractContextManager[M8FeishuResolvedSecrets]: ...


__all__ = ["M8FeishuResolvedSecrets", "M8FeishuSecretResolver"]
