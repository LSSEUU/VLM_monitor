from __future__ import annotations

import base64
import hashlib
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from labcourt.adapters.m8_feishu_inbound_cryptography import (
    CryptographyM8FeishuInboundCrypto,
)
from labcourt.adapters.m8_feishu_inbound_environment_secrets import (
    EnvironmentM8FeishuInboundSecretResolver,
    M8FeishuInboundEnvironmentSecretBinding,
)
from labcourt.adapters.storage.sqlite_m8_feishu_inbound_repository import (
    SQLiteM8FeishuInboundRepository,
)
from labcourt.adapters.storage.sqlite_repository import RepositoryIntegrityError
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.m8_feishu_inbound import (
    M8FeishuInboundWebhookProfileV1,
    M8FeishuWebhookIngressRequestV1,
)
from labcourt.exceptions import ConcurrentModification, ContractViolation, EvidenceMissing
from labcourt.ports.m8_feishu_inbound_crypto import M8FeishuInboundCryptoError
from labcourt.ports.m8_feishu_inbound_secrets import M8FeishuInboundResolvedSecrets
from labcourt.services.m8_feishu_inbound import M8FeishuInboundVerificationService
from tests.contract.test_m8_feishu_notification_contracts import (
    FAKE_FEISHU_APP_ID,
    _profile,
)

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SHA_E = "e" * 64
RECEIVED_AT = datetime(2026, 8, 11, 16, 0, tzinfo=UTC)
ENCRYPT_KEY = b"fake-feishu-encrypt-key-fixture-01"
VERIFICATION_TOKEN = b"fake-feishu-verification-token-01"
CIPHERTEXT = b"0123456789abcdef" + b"fedcba9876543210"
BUSY_TIMEOUT_MS = 5_000


class _SecretResolver:
    def __init__(self) -> None:
        self.leases: list[M8FeishuInboundResolvedSecrets] = []

    def resolve(
        self,
        profile: M8FeishuInboundWebhookProfileV1,
    ) -> M8FeishuInboundResolvedSecrets:
        lease = M8FeishuInboundResolvedSecrets(
            inbound_profile_id=profile.inbound_profile_id,
            encrypt_key_reference_id=profile.encrypt_key_reference_id,
            verification_token_reference_id=profile.verification_token_reference_id,
            encrypt_key=ENCRYPT_KEY,
            verification_token=VERIFICATION_TOKEN,
        )
        self.leases.append(lease)
        return lease


class _Crypto:
    def __init__(self, decrypted_event: bytes, *, fail: bool = False) -> None:
        self.decrypted_event = decrypted_event
        self.fail = fail
        self.calls = 0

    def decrypt_aes_256_cbc(
        self,
        ciphertext_with_iv: bytes,
        key_sha256: bytes,
    ) -> bytes:
        self.calls += 1
        assert ciphertext_with_iv == CIPHERTEXT
        assert key_sha256 == hashlib.sha256(ENCRYPT_KEY).digest()
        if self.fail:
            raise M8FeishuInboundCryptoError("sanitized fake decrypt failure")
        return self.decrypted_event


def _webhook_profile() -> M8FeishuInboundWebhookProfileV1:
    return M8FeishuInboundWebhookProfileV1(
        outbound_profile=_profile(),
        request_url_reference_id="feishu-inbound-url-sandbox-01",
        encrypt_key_reference_id="secret-feishu-encrypt-key-01",
        encrypt_key_sha256=hashlib.sha256(ENCRYPT_KEY).hexdigest(),
        verification_token_reference_id="secret-feishu-verification-token-01",
        verification_token_sha256=hashlib.sha256(VERIFICATION_TOKEN).hexdigest(),
        profile_manifest_id=SHA_A,
    )


def _event_bytes(
    *,
    event_id: str = "event-sandbox-01",
    message_id: str = "om_student_reply_01",
    text: str = "student explanation fixture",
    token: bytes = VERIFICATION_TOKEN,
    chat_type: str = "p2p",
    extra_header: bool = False,
) -> bytes:
    header = {
        "app_id": FAKE_FEISHU_APP_ID.decode(),
        "create_time": str(int((RECEIVED_AT - timedelta(seconds=2)).timestamp() * 1_000)),
        "event_id": event_id,
        "event_type": "im.message.receive_v1",
        "tenant_key": "tenant-sandbox-01",
        "token": token.decode(),
    }
    if extra_header:
        header["unexpected"] = "rejected"
    return canonical_json(
        {
            "event": {
                "message": {
                    "chat_id": "oc_student_bot_p2p_01",
                    "chat_type": chat_type,
                    "content": canonical_json({"text": text}),
                    "create_time": str(
                        int((RECEIVED_AT - timedelta(seconds=3)).timestamp() * 1_000)
                    ),
                    "message_id": message_id,
                    "message_type": "text",
                    "parent_id": "om_outbound_case_card_01",
                    "root_id": "om_outbound_case_card_01",
                },
                "sender": {
                    "sender_id": {"open_id": "ou_fake_labcourt_student"},
                    "sender_type": "user",
                    "tenant_key": "tenant-sandbox-01",
                },
            },
            "header": header,
            "schema": "2.0",
        }
    ).encode()


def _encrypted_body() -> bytes:
    return canonical_json({"encrypt": base64.b64encode(CIPHERTEXT).decode()}).encode()


def _ingress(
    profile: M8FeishuInboundWebhookProfileV1,
    body: bytes,
    *,
    signature: str | None = None,
) -> M8FeishuWebhookIngressRequestV1:
    nonce = "nonce-sandbox-01"
    timestamp = int(RECEIVED_AT.timestamp())
    calculated = hashlib.sha256(
        str(timestamp).encode() + nonce.encode() + ENCRYPT_KEY + body
    ).hexdigest()
    return M8FeishuWebhookIngressRequestV1(
        inbound_profile_id=profile.inbound_profile_id,
        request_timestamp_seconds=timestamp,
        request_nonce=nonce,
        request_signature=signature or calculated,
        encrypted_body_ref="feishu-encrypted-event-01",
        encrypted_body_sha256=hashlib.sha256(body).hexdigest(),
        encrypted_body_size_bytes=len(body),
        received_at=RECEIVED_AT,
        ingress_manifest_id=SHA_B,
    )


def _repository(tmp_path: Path) -> SQLiteM8FeishuInboundRepository:
    return SQLiteM8FeishuInboundRepository.initialize(
        tmp_path / "labcourt.sqlite3",
        BUSY_TIMEOUT_MS,
        SHA_C,
    )


def _service(
    repository: SQLiteM8FeishuInboundRepository,
    crypto: _Crypto,
    resolver: _SecretResolver | None = None,
) -> M8FeishuInboundVerificationService:
    return M8FeishuInboundVerificationService(
        repository,
        resolver or _SecretResolver(),
        crypto,
        lambda: RECEIVED_AT + timedelta(seconds=1),
        SHA_D,
        SHA_E,
        SHA_A,
    )


def test_verification_commits_exact_raw_inventory_and_restarts(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    profile = _webhook_profile()
    body = _encrypted_body()
    event = _event_bytes()
    crypto = _Crypto(event)
    resolver = _SecretResolver()
    service = _service(repository, crypto, resolver)

    committed = service.verify_and_commit(profile, _ingress(profile, body), body)
    assert committed.provider_message_id == "om_student_reply_01"
    assert committed.verification_receipt.reply_correlation_message_id == (
        "om_outbound_case_card_01"
    )
    assert committed.verification_receipt.provider_message_deduplication_key == (
        "om_student_reply_01"
    )
    assert committed.notification_reply_commit_permitted is False
    assert committed.case_transition_permitted is False
    assert crypto.calls == 1
    assert "closed=True" in repr(resolver.leases[0])
    with pytest.raises(RuntimeError, match="lease is closed"):
        resolver.leases[0].encrypt_key_bytes()

    raws = tuple(repository.read_raw_artifact(ref) for ref in committed.raw_artifact_refs)
    assert raws == (
        body,
        event,
        canonical_json({"text": "student explanation fixture"}).encode(),
    )
    assert repository.get_by_provider_message_id(committed.provider_message_id) == committed
    restarted = SQLiteM8FeishuInboundRepository(
        tmp_path / "labcourt.sqlite3",
        BUSY_TIMEOUT_MS,
        SHA_C,
    )
    assert restarted.get_by_provider_message_id(committed.provider_message_id) == committed
    assert service.verify_and_commit(profile, _ingress(profile, body), body) == committed


def test_environment_resolver_plugs_into_offline_verification_service(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    profile = _webhook_profile()
    body = _encrypted_body()
    binding = M8FeishuInboundEnvironmentSecretBinding(
        inbound_profile_id=profile.inbound_profile_id,
        encrypt_key_reference_id=profile.encrypt_key_reference_id,
        verification_token_reference_id=profile.verification_token_reference_id,
        encrypt_key_env="LABCOURT_TEST_FEISHU_INBOUND_ENCRYPT_KEY",
        verification_token_env="LABCOURT_TEST_FEISHU_INBOUND_VERIFICATION_TOKEN",
    )
    resolver = EnvironmentM8FeishuInboundSecretResolver(
        (binding,),
        environment={
            binding.encrypt_key_env: ENCRYPT_KEY.decode(),
            binding.verification_token_env: VERIFICATION_TOKEN.decode(),
        },
    )
    service = _service(repository, _Crypto(_event_bytes()), resolver)

    committed = service.verify_and_commit(profile, _ingress(profile, body), body)

    assert committed.provider_message_id == "om_student_reply_01"
    assert ENCRYPT_KEY.decode() not in repr(resolver)
    assert VERIFICATION_TOKEN.decode() not in repr(resolver)


def test_optional_cryptography_adapter_verifies_a_full_encrypted_event(tmp_path: Path) -> None:
    padding = pytest.importorskip("cryptography.hazmat.primitives.padding")
    ciphers = pytest.importorskip("cryptography.hazmat.primitives.ciphers")
    algorithms = pytest.importorskip("cryptography.hazmat.primitives.ciphers.algorithms")
    modes = pytest.importorskip("cryptography.hazmat.primitives.ciphers.modes")
    event = _event_bytes()
    padder = padding.PKCS7(128).padder()
    padded = padder.update(event) + padder.finalize()
    iv = b"0123456789abcdef"
    encryptor = ciphers.Cipher(
        algorithms.AES256(hashlib.sha256(ENCRYPT_KEY).digest()),
        modes.CBC(iv),
    ).encryptor()
    encrypted_event = iv + encryptor.update(padded) + encryptor.finalize()
    body = canonical_json({"encrypt": base64.b64encode(encrypted_event).decode()}).encode()
    repository = _repository(tmp_path)
    profile = _webhook_profile()
    service = M8FeishuInboundVerificationService(
        repository,
        _SecretResolver(),
        CryptographyM8FeishuInboundCrypto(),
        lambda: RECEIVED_AT + timedelta(seconds=1),
        SHA_D,
        SHA_E,
        SHA_A,
    )

    committed = service.verify_and_commit(profile, _ingress(profile, body), body)

    assert committed.provider_message_id == "om_student_reply_01"
    assert repository.read_raw_artifact(committed.raw_artifact_refs[1]) == event


@pytest.mark.parametrize(
    "event",
    (
        _event_bytes(token=b"wrong-verification-token"),
        _event_bytes(chat_type="group"),
        _event_bytes(extra_header=True),
    ),
)
def test_invalid_decrypted_event_never_commits(tmp_path: Path, event: bytes) -> None:
    repository = _repository(tmp_path)
    profile = _webhook_profile()
    body = _encrypted_body()

    with pytest.raises(ContractViolation):
        _service(repository, _Crypto(event)).verify_and_commit(
            profile,
            _ingress(profile, body),
            body,
        )
    with pytest.raises(EvidenceMissing):
        repository.get_by_provider_message_id("om_student_reply_01")


def test_bad_signature_blocks_before_decrypt_and_secret_lease_closes(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    profile = _webhook_profile()
    body = _encrypted_body()
    crypto = _Crypto(_event_bytes())
    resolver = _SecretResolver()

    with pytest.raises(ContractViolation, match="signature is invalid"):
        _service(repository, crypto, resolver).verify_and_commit(
            profile,
            _ingress(profile, body, signature=SHA_E),
            body,
        )
    assert crypto.calls == 0
    assert "closed=True" in repr(resolver.leases[0])


def test_stale_request_and_crypto_failure_are_typed_without_commit(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    profile = _webhook_profile()
    body = _encrypted_body()
    stale = _ingress(profile, body).model_copy(
        update={
            "request_timestamp_seconds": int(
                (RECEIVED_AT - timedelta(minutes=6)).timestamp()
            )
        }
    )
    resolver = _SecretResolver()
    crypto = _Crypto(_event_bytes())
    with pytest.raises(ContractViolation, match="freshness window"):
        _service(repository, crypto, resolver).verify_and_commit(profile, stale, body)
    assert resolver.leases == []
    assert crypto.calls == 0

    with pytest.raises(ContractViolation, match="decryption failed"):
        _service(repository, _Crypto(_event_bytes(), fail=True)).verify_and_commit(
            profile,
            _ingress(profile, body),
            body,
        )
    with pytest.raises(EvidenceMissing):
        repository.get_by_provider_message_id("om_student_reply_01")


def test_provider_message_replay_with_different_evidence_conflicts(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    profile = _webhook_profile()
    body = _encrypted_body()
    first = _service(repository, _Crypto(_event_bytes())).verify_and_commit(
        profile,
        _ingress(profile, body),
        body,
    )
    different_event = _event_bytes(
        event_id="event-sandbox-02",
        text="different student explanation fixture",
    )

    with pytest.raises(ConcurrentModification, match="committed differently"):
        _service(repository, _Crypto(different_event)).verify_and_commit(
            profile,
            _ingress(profile, body),
            body,
        )
    assert repository.get_by_provider_message_id(first.provider_message_id) == first


def test_sql_rows_are_append_only_and_missing_raw_fails_closed(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    profile = _webhook_profile()
    body = _encrypted_body()
    committed = _service(repository, _Crypto(_event_bytes())).verify_and_commit(
        profile,
        _ingress(profile, body),
        body,
    )
    database = tmp_path / "labcourt.sqlite3"

    with sqlite3.connect(database) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "UPDATE m8_feishu_inbound_message_commits SET provider_event_id = ?",
                ("event-tampered-01",),
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "DELETE FROM m8_feishu_inbound_raw_artifacts WHERE raw_artifact_ref = ?",
                (committed.raw_artifact_refs[0],),
            )

    with sqlite3.connect(database) as connection:
        connection.execute("DROP TRIGGER m8_feishu_inbound_raw_artifacts_no_delete")
        connection.execute(
            "DELETE FROM m8_feishu_inbound_raw_artifacts WHERE raw_artifact_ref = ?",
            (committed.raw_artifact_refs[0],),
        )
    with pytest.raises(RepositoryIntegrityError, match="raw inventory is incomplete"):
        repository.get_by_provider_message_id(committed.provider_message_id)
