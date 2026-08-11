from __future__ import annotations

import base64
import hashlib
from datetime import timedelta

import pytest

from labcourt.adapters.m8_feishu_inbound_cryptography import (
    CryptographyM8FeishuInboundCrypto,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m8_feishu_challenge import M8FeishuUrlChallengeIngressRequestV1
from labcourt.exceptions import ContractViolation
from labcourt.services.m8_feishu_challenge import M8FeishuUrlChallengeService
from tests.integration.test_m8_feishu_inbound_verification import (
    CIPHERTEXT,
    ENCRYPT_KEY,
    RECEIVED_AT,
    VERIFICATION_TOKEN,
    _Crypto,
    _SecretResolver,
    _webhook_profile,
)

SHA_A = "a" * 64
SHA_B = "b" * 64


def _challenge_bytes(
    *,
    challenge: str = "challenge-clear-fixture",
    token: bytes = VERIFICATION_TOKEN,
    challenge_type: str = "url_verification",
    extra: bool = False,
) -> bytes:
    value = {
        "challenge": challenge,
        "token": token.decode(),
        "type": challenge_type,
    }
    if extra:
        value["unexpected"] = "rejected"
    return canonical_json(value).encode()


def _encrypted_body(ciphertext: bytes = CIPHERTEXT) -> bytes:
    return canonical_json({"encrypt": base64.b64encode(ciphertext).decode()}).encode()


def _ingress(body: bytes) -> M8FeishuUrlChallengeIngressRequestV1:
    return M8FeishuUrlChallengeIngressRequestV1(
        inbound_profile_id=_webhook_profile().inbound_profile_id,
        encrypted_body_ref="feishu-encrypted-url-challenge-01",
        encrypted_body_sha256=hashlib.sha256(body).hexdigest(),
        encrypted_body_size_bytes=len(body),
        received_at=RECEIVED_AT,
        ingress_manifest_id=SHA_A,
    )


def _service(decrypted: bytes, *, delay_milliseconds: int = 10) -> M8FeishuUrlChallengeService:
    return M8FeishuUrlChallengeService(
        _SecretResolver(),
        _Crypto(decrypted),
        lambda: RECEIVED_AT + timedelta(milliseconds=delay_milliseconds),
        SHA_B,
    )


def test_verified_challenge_returns_only_exact_canonical_json() -> None:
    profile = _webhook_profile()
    body = _encrypted_body()

    result = _service(_challenge_bytes()).verify(profile, _ingress(body), body)

    assert result.response_body() == b'{"challenge":"challenge-clear-fixture"}'
    assert result.receipt.challenge_response_permitted is True
    assert result.receipt.external_ingress_activation_permitted is False
    assert result.receipt.notification_reply_commit_permitted is False
    assert result.receipt.case_transition_permitted is False
    assert "challenge-clear-fixture" not in result.receipt.model_dump_json()
    assert "challenge-clear-fixture" not in repr(result)


@pytest.mark.parametrize(
    ("decrypted", "message"),
    (
        (_challenge_bytes(token=b"wrong-verification-token"), "token is invalid"),
        (_challenge_bytes(challenge_type="business_event"), "payload is invalid"),
        (_challenge_bytes(extra=True), "payload is invalid"),
        (_challenge_bytes(challenge=""), "payload is invalid"),
    ),
)
def test_invalid_challenge_never_authorizes_response(
    decrypted: bytes,
    message: str,
) -> None:
    profile = _webhook_profile()
    body = _encrypted_body()

    with pytest.raises(ContractViolation, match=message):
        _service(decrypted).verify(profile, _ingress(body), body)


def test_changed_body_and_missed_deadline_fail_closed() -> None:
    profile = _webhook_profile()
    body = _encrypted_body()

    with pytest.raises(ContractViolation, match="request bytes changed"):
        _service(_challenge_bytes()).verify(profile, _ingress(body), body + b" ")
    with pytest.raises(ContractViolation, match="receipt is invalid"):
        _service(_challenge_bytes(), delay_milliseconds=1_001).verify(
            profile,
            _ingress(body),
            body,
        )


def test_optional_cryptography_adapter_decrypts_full_challenge() -> None:
    padding = pytest.importorskip("cryptography.hazmat.primitives.padding")
    ciphers = pytest.importorskip("cryptography.hazmat.primitives.ciphers")
    algorithms = pytest.importorskip("cryptography.hazmat.primitives.ciphers.algorithms")
    modes = pytest.importorskip("cryptography.hazmat.primitives.ciphers.modes")
    decrypted = _challenge_bytes()
    padder = padding.PKCS7(128).padder()
    padded = padder.update(decrypted) + padder.finalize()
    iv = b"0123456789abcdef"
    encryptor = ciphers.Cipher(
        algorithms.AES256(hashlib.sha256(ENCRYPT_KEY).digest()),
        modes.CBC(iv),
    ).encryptor()
    encrypted = iv + encryptor.update(padded) + encryptor.finalize()
    body = _encrypted_body(encrypted)
    service = M8FeishuUrlChallengeService(
        _SecretResolver(),
        CryptographyM8FeishuInboundCrypto(),
        lambda: RECEIVED_AT + timedelta(milliseconds=10),
        SHA_B,
    )

    result = service.verify(_webhook_profile(), _ingress(body), body)

    assert result.response_body() == b'{"challenge":"challenge-clear-fixture"}'
