from __future__ import annotations

import base64
import hashlib
import http.client
import json
import sqlite3
import threading
from pathlib import Path

from labcourt.application.m8_feishu_webhook_runtime import (
    build_m8_feishu_webhook_runtime,
)
from tests.integration.test_m8_feishu_activated_webhook_server import _running_server
from tests.integration.test_m8_feishu_challenge import _challenge_bytes
from tests.integration.test_m8_feishu_inbound_verification import (
    ENCRYPT_KEY,
    RECEIVED_AT,
    VERIFICATION_TOKEN,
)
from tests.integration.test_m8_sqlite_feishu_activation_repository import (
    BUSY_TIMEOUT_MS,
    SHA_A,
    _candidate,
)


def _real_encrypted_body() -> bytes:
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    plaintext = _challenge_bytes()
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    iv = b"0123456789abcdef"
    encryptor = Cipher(
        algorithms.AES256(hashlib.sha256(ENCRYPT_KEY).digest()),
        modes.CBC(iv),
    ).encryptor()
    encrypted = iv + encryptor.update(padded) + encryptor.finalize()
    return json.dumps(
        {"encrypt": base64.b64encode(encrypted).decode()},
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def test_runtime_assembles_current_sqlite_authority_environment_secrets_and_aes(
    tmp_path: Path,
    socket_enabled: None,
    monkeypatch,
) -> None:
    del socket_enabled
    with _running_server(tmp_path):
        pass
    monkeypatch.setenv("LABCOURT_TEST_FEISHU_RUNTIME_ENCRYPT_KEY", ENCRYPT_KEY.decode())
    monkeypatch.setenv(
        "LABCOURT_TEST_FEISHU_RUNTIME_VERIFICATION_TOKEN",
        VERIFICATION_TOKEN.decode(),
    )
    database = tmp_path / "labcourt.sqlite3"
    assembly = build_m8_feishu_webhook_runtime(
        database_path=database,
        candidate_authority_id=_candidate().candidate_authority_id,
        encrypt_key_env="LABCOURT_TEST_FEISHU_RUNTIME_ENCRYPT_KEY",
        verification_token_env="LABCOURT_TEST_FEISHU_RUNTIME_VERIFICATION_TOKEN",
        runtime_manifest_id=SHA_A,
        busy_timeout_ms=BUSY_TIMEOUT_MS,
        clock=lambda: RECEIVED_AT,
    )
    assert assembly.server.server_address[0] == "127.0.0.1"
    assert assembly.activation_status.sandbox_external_ingress_permitted is True
    assert ENCRYPT_KEY.decode() not in repr(assembly)
    assert VERIFICATION_TOKEN.decode() not in repr(assembly)

    thread = threading.Thread(target=assembly.server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = http.client.HTTPConnection(
            "127.0.0.1",
            assembly.server.server_port,
            timeout=3,
        )
        body = _real_encrypted_body()
        connection.request(
            "POST",
            "/callbacks/feishu/v1",
            body=body,
            headers={"Content-Type": "application/json"},
        )
        response = connection.getresponse()
        payload = json.loads(response.read())
        connection.close()
        assert response.status == 200
        assert payload == {"challenge": "challenge-clear-fixture"}
    finally:
        assembly.server.shutdown()
        assembly.server.server_close()
        thread.join(timeout=3)

    with sqlite3.connect(database) as connection:
        count = connection.execute(
            "SELECT COUNT(*) FROM m8_feishu_url_challenge_commits"
        ).fetchone()[0]
    assert count == 1
