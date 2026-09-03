"""Strict offline verification of Feishu encrypted URL challenges."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
from collections.abc import Callable
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictStr, ValidationError

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_feishu_challenge import (
    M8FeishuUrlChallengeIngressRequestV1,
    M8FeishuUrlChallengeVerificationReceiptV1,
)
from labcourt.contracts.m8_feishu_inbound import (
    MAX_M8_FEISHU_INBOUND_BODY_BYTES,
    M8FeishuInboundWebhookProfileV1,
)
from labcourt.exceptions import ContractViolation
from labcourt.ports.m8_feishu_inbound_crypto import (
    M8FeishuInboundCrypto,
    M8FeishuInboundCryptoError,
)
from labcourt.ports.m8_feishu_inbound_secrets import M8FeishuInboundSecretResolver


class _EncryptedEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    encrypt: StrictStr


class _UrlChallengeEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    challenge: StrictStr = Field(min_length=1, max_length=2_048)
    type: Literal["url_verification"]
    token: StrictStr = Field(min_length=1, max_length=2_048)


def _artifact_ref(prefix: str, raw: bytes) -> str:
    digest = hashlib.sha256(raw).hexdigest()
    return f"{prefix}{digest[: 64 - len(prefix)]}"


class M8FeishuUrlChallengeResult:
    """Runtime-only clear response paired with its secret-free authority receipt."""

    __slots__ = ("_response_body", "receipt")

    def __init__(
        self,
        receipt: M8FeishuUrlChallengeVerificationReceiptV1,
        response_body: bytes,
    ) -> None:
        if not isinstance(receipt, M8FeishuUrlChallengeVerificationReceiptV1):
            raise TypeError("M8 Feishu URL challenge result requires a typed receipt")
        if not isinstance(response_body, bytes) or not response_body:
            raise TypeError("M8 Feishu URL challenge result requires exact response bytes")
        if (
            hashlib.sha256(response_body).hexdigest() != receipt.response_document_sha256
            or len(response_body) != receipt.response_document_size_bytes
        ):
            raise ContractViolation("M8 Feishu URL challenge response bytes changed")
        self.receipt = receipt
        self._response_body = response_body

    def response_body(self) -> bytes:
        return self._response_body

    def __repr__(self) -> str:
        return (
            "M8FeishuUrlChallengeResult("
            f"receipt_id={self.receipt.verification_receipt_id!r}, response_body=<redacted>)"
        )


class M8FeishuUrlChallengeService:
    """Decrypt and authorize only the exact URL challenge JSON response."""

    def __init__(
        self,
        secret_resolver: M8FeishuInboundSecretResolver,
        crypto: M8FeishuInboundCrypto,
        clock: Callable[[], datetime],
        verification_manifest_id: Sha256Hex,
    ) -> None:
        if secret_resolver is None or crypto is None:
            raise TypeError("M8 Feishu URL challenge verification requires explicit ports")
        if not callable(clock):
            raise TypeError("M8 Feishu URL challenge verification requires a clock")
        if (
            not isinstance(verification_manifest_id, str)
            or len(verification_manifest_id) != 64
            or any(character not in "0123456789abcdef" for character in verification_manifest_id)
        ):
            raise ValueError(
                "M8 Feishu URL challenge verification manifest must be lowercase SHA-256 hex"
            )
        self._secrets = secret_resolver
        self._crypto = crypto
        self._clock = clock
        self._verification_manifest_id = verification_manifest_id

    def verify(
        self,
        profile: M8FeishuInboundWebhookProfileV1,
        ingress_request: M8FeishuUrlChallengeIngressRequestV1,
        encrypted_body: bytes,
    ) -> M8FeishuUrlChallengeResult:
        if not isinstance(profile, M8FeishuInboundWebhookProfileV1):
            raise TypeError("M8 Feishu URL challenge verification requires a typed profile")
        if not isinstance(ingress_request, M8FeishuUrlChallengeIngressRequestV1):
            raise TypeError("M8 Feishu URL challenge verification requires typed ingress")
        if not isinstance(encrypted_body, bytes):
            raise TypeError("M8 Feishu URL challenge verification requires exact request bytes")
        if ingress_request.inbound_profile_id != profile.inbound_profile_id:
            raise ContractViolation("M8 Feishu URL challenge belongs to another profile")
        if (
            not encrypted_body
            or len(encrypted_body) != ingress_request.encrypted_body_size_bytes
            or len(encrypted_body) > profile.raw_body_max_bytes
            or hashlib.sha256(encrypted_body).hexdigest() != ingress_request.encrypted_body_sha256
        ):
            raise ContractViolation("M8 Feishu URL challenge request bytes changed")

        with self._secrets.resolve(profile) as secrets:
            encrypt_key = secrets.encrypt_key_bytes()
            verification_token = secrets.verification_token_bytes()
            self._validate_secrets(profile, secrets, encrypt_key, verification_token)
            ciphertext = self._parse_encrypted_body(encrypted_body)
            try:
                decrypted = self._crypto.decrypt_aes_256_cbc(
                    ciphertext,
                    hashlib.sha256(encrypt_key).digest(),
                )
            except M8FeishuInboundCryptoError as error:
                raise ContractViolation("M8 Feishu URL challenge decryption failed") from error
            challenge = self._parse_challenge(profile, verification_token, decrypted)

        response_body = canonical_json({"challenge": challenge.challenge}).encode("utf-8")
        if len(response_body) > profile.raw_body_max_bytes:
            raise ContractViolation("M8 Feishu URL challenge response exceeds its bound")
        try:
            receipt = M8FeishuUrlChallengeVerificationReceiptV1(
                profile=profile,
                ingress_request=ingress_request,
                decrypted_challenge_ref=_artifact_ref(
                    "m8-feishu-url-challenge-",
                    decrypted,
                ),
                decrypted_challenge_sha256=hashlib.sha256(decrypted).hexdigest(),
                decrypted_challenge_size_bytes=len(decrypted),
                response_document_ref=_artifact_ref(
                    "m8-feishu-url-response-",
                    response_body,
                ),
                response_document_sha256=hashlib.sha256(response_body).hexdigest(),
                response_document_size_bytes=len(response_body),
                verification_token_sha256=hashlib.sha256(verification_token).hexdigest(),
                verified_at=self._clock(),
                verification_manifest_id=self._verification_manifest_id,
            )
        except ValidationError as error:
            raise ContractViolation("M8 Feishu URL challenge receipt is invalid") from error
        return M8FeishuUrlChallengeResult(receipt, response_body)

    @staticmethod
    def _validate_secrets(
        profile: M8FeishuInboundWebhookProfileV1,
        secrets: object,
        encrypt_key: bytes,
        verification_token: bytes,
    ) -> None:
        if (
            getattr(secrets, "inbound_profile_id", None) != profile.inbound_profile_id
            or getattr(secrets, "encrypt_key_reference_id", None)
            != profile.encrypt_key_reference_id
            or getattr(secrets, "verification_token_reference_id", None)
            != profile.verification_token_reference_id
            or not encrypt_key
            or not verification_token
            or not hmac.compare_digest(
                hashlib.sha256(encrypt_key).hexdigest(),
                profile.encrypt_key_sha256,
            )
            or not hmac.compare_digest(
                hashlib.sha256(verification_token).hexdigest(),
                profile.verification_token_sha256,
            )
        ):
            raise ContractViolation("M8 Feishu URL challenge secret authority mismatch")

    @staticmethod
    def _parse_encrypted_body(encrypted_body: bytes) -> bytes:
        try:
            envelope = _EncryptedEnvelope.model_validate_json(encrypted_body)
            encoded = envelope.encrypt.encode("ascii")
            ciphertext = base64.b64decode(encoded, validate=True)
        except (ValidationError, UnicodeEncodeError, binascii.Error) as error:
            raise ContractViolation("M8 Feishu URL challenge envelope is invalid") from error
        if (
            len(ciphertext) < 32
            or len(ciphertext) > MAX_M8_FEISHU_INBOUND_BODY_BYTES
            or (len(ciphertext) - 16) % 16 != 0
        ):
            raise ContractViolation("M8 Feishu URL challenge ciphertext is invalid")
        return ciphertext

    @staticmethod
    def _parse_challenge(
        profile: M8FeishuInboundWebhookProfileV1,
        verification_token: bytes,
        decrypted: bytes,
    ) -> _UrlChallengeEnvelope:
        if not decrypted or len(decrypted) > profile.raw_body_max_bytes:
            raise ContractViolation("M8 Feishu URL challenge payload is outside its bound")
        try:
            challenge = _UrlChallengeEnvelope.model_validate_json(decrypted)
            token = challenge.token.encode("utf-8")
        except (ValidationError, UnicodeEncodeError) as error:
            raise ContractViolation("M8 Feishu URL challenge payload is invalid") from error
        if not hmac.compare_digest(token, verification_token):
            raise ContractViolation("M8 Feishu URL challenge verification token is invalid")
        return challenge


__all__ = ["M8FeishuUrlChallengeResult", "M8FeishuUrlChallengeService"]
