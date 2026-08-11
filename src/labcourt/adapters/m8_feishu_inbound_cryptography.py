"""Optional PyCA-backed AES-256-CBC primitive for Feishu encrypted events."""

from __future__ import annotations

from labcourt.contracts.m8_feishu_inbound import MAX_M8_FEISHU_INBOUND_BODY_BYTES
from labcourt.ports.m8_feishu_inbound_crypto import M8FeishuInboundCryptoError

_AES_BLOCK_BYTES = 16
_AES_256_KEY_BYTES = 32


class CryptographyM8FeishuInboundCrypto:
    """Strict adapter over the optional, audited ``cryptography`` package."""

    def __repr__(self) -> str:
        return "CryptographyM8FeishuInboundCrypto(provider=pyca, values_redacted=True)"

    def decrypt_aes_256_cbc(
        self,
        ciphertext_with_iv: bytes,
        key_sha256: bytes,
    ) -> bytes:
        if not isinstance(ciphertext_with_iv, bytes) or not isinstance(key_sha256, bytes):
            raise TypeError("M8 Feishu inbound crypto requires exact bytes")
        if len(key_sha256) != _AES_256_KEY_BYTES:
            raise M8FeishuInboundCryptoError(
                "M8 Feishu inbound AES-256 key digest has invalid length"
            )
        ciphertext_size = len(ciphertext_with_iv) - _AES_BLOCK_BYTES
        if (
            len(ciphertext_with_iv) > MAX_M8_FEISHU_INBOUND_BODY_BYTES
            or ciphertext_size < _AES_BLOCK_BYTES
            or ciphertext_size % _AES_BLOCK_BYTES != 0
        ):
            raise M8FeishuInboundCryptoError(
                "M8 Feishu inbound AES-CBC ciphertext has invalid length"
            )
        try:
            from cryptography.hazmat.primitives import padding
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        except ImportError as error:
            raise M8FeishuInboundCryptoError(
                "M8 Feishu inbound cryptography provider is unavailable"
            ) from error

        iv = ciphertext_with_iv[:_AES_BLOCK_BYTES]
        ciphertext = ciphertext_with_iv[_AES_BLOCK_BYTES:]
        try:
            decryptor = Cipher(
                algorithms.AES256(key_sha256),
                modes.CBC(iv),
            ).decryptor()
            padded = decryptor.update(ciphertext) + decryptor.finalize()
            unpadder = padding.PKCS7(_AES_BLOCK_BYTES * 8).unpadder()
            plaintext = unpadder.update(padded) + unpadder.finalize()
        except ValueError as error:
            raise M8FeishuInboundCryptoError(
                "M8 Feishu inbound AES-CBC decryption failed"
            ) from error
        if not isinstance(plaintext, bytes) or not plaintext:
            raise M8FeishuInboundCryptoError(
                "M8 Feishu inbound AES-CBC plaintext is empty or invalid"
            )
        if len(plaintext) > MAX_M8_FEISHU_INBOUND_BODY_BYTES:
            raise M8FeishuInboundCryptoError(
                "M8 Feishu inbound AES-CBC plaintext exceeds the allowed bound"
            )
        return plaintext


__all__ = ["CryptographyM8FeishuInboundCrypto"]
