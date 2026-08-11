from __future__ import annotations

import base64
import builtins
import hashlib
from typing import Any

import pytest

pytest.importorskip("cryptography")

from labcourt.adapters.m8_feishu_inbound_cryptography import (
    CryptographyM8FeishuInboundCrypto,
)
from labcourt.ports.m8_feishu_inbound_crypto import (
    M8FeishuInboundCryptoError,
)

OFFICIAL_FEISHU_ENCRYPTED_FIXTURE = "P37w+VZImNgPEO1RBhJ6RtKl7n6zymIbEG1pReEzghk="


def test_official_feishu_fixture_decrypts_with_strict_pkcs7() -> None:
    adapter = CryptographyM8FeishuInboundCrypto()
    encrypted = base64.b64decode(OFFICIAL_FEISHU_ENCRYPTED_FIXTURE)
    key = hashlib.sha256(b"test key").digest()

    assert adapter.decrypt_aes_256_cbc(encrypted, key) == b"hello world"
    assert "values_redacted=True" in repr(adapter)
    assert OFFICIAL_FEISHU_ENCRYPTED_FIXTURE not in repr(adapter)


def test_adapter_rejects_bad_padding_or_key_and_ciphertext_lengths() -> None:
    adapter = CryptographyM8FeishuInboundCrypto()
    encrypted = base64.b64decode(OFFICIAL_FEISHU_ENCRYPTED_FIXTURE)
    key = hashlib.sha256(b"test key").digest()

    corrupted = encrypted[:-1] + bytes([encrypted[-1] ^ 0xFF])
    with pytest.raises(M8FeishuInboundCryptoError, match="decryption failed"):
        adapter.decrypt_aes_256_cbc(corrupted, key)
    with pytest.raises(M8FeishuInboundCryptoError, match="key digest"):
        adapter.decrypt_aes_256_cbc(encrypted, key[:-1])
    with pytest.raises(M8FeishuInboundCryptoError, match="ciphertext"):
        adapter.decrypt_aes_256_cbc(encrypted[:-1], key)
    with pytest.raises(TypeError, match="exact bytes"):
        adapter.decrypt_aes_256_cbc(bytearray(encrypted), key)  # type: ignore[arg-type]


def test_missing_optional_provider_is_a_typed_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter = CryptographyM8FeishuInboundCrypto()
    encrypted = base64.b64decode(OFFICIAL_FEISHU_ENCRYPTED_FIXTURE)
    key = hashlib.sha256(b"test key").digest()
    original_import = builtins.__import__

    def blocked_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "cryptography" or name.startswith("cryptography."):
            raise ImportError("blocked optional dependency")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocked_import)
    with pytest.raises(M8FeishuInboundCryptoError, match="provider is unavailable"):
        adapter.decrypt_aes_256_cbc(encrypted, key)
