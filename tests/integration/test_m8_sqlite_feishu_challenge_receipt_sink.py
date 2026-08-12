from __future__ import annotations

import sqlite3
from datetime import timedelta
from pathlib import Path

import pytest

from labcourt.adapters.storage.sqlite_m8_feishu_challenge_receipt_sink import (
    SQLiteM8FeishuUrlChallengeReceiptSink,
)
from labcourt.adapters.storage.sqlite_repository import RepositoryIntegrityError
from labcourt.services.m8_feishu_challenge import M8FeishuUrlChallengeService
from tests.integration.test_m8_feishu_challenge import (
    SHA_A,
    SHA_B,
    _challenge_bytes,
    _encrypted_body,
    _ingress,
)
from tests.integration.test_m8_feishu_inbound_verification import (
    BUSY_TIMEOUT_MS,
    RECEIVED_AT,
    _Crypto,
    _SecretResolver,
    _webhook_profile,
)


def _verified():
    body = _encrypted_body()
    service = M8FeishuUrlChallengeService(
        _SecretResolver(),
        _Crypto(_challenge_bytes()),
        lambda: RECEIVED_AT + timedelta(milliseconds=10),
        SHA_B,
    )
    return service.verify(_webhook_profile(), _ingress(body), body).receipt


def test_challenge_audit_is_restart_safe_idempotent_and_append_only(
    tmp_path: Path,
) -> None:
    database = tmp_path / "labcourt.sqlite3"
    sink = SQLiteM8FeishuUrlChallengeReceiptSink.initialize(
        database,
        BUSY_TIMEOUT_MS,
        SHA_A,
        SHA_B,
        lambda: RECEIVED_AT + timedelta(milliseconds=20),
    )
    verified = _verified()

    committed = sink.record_verification(verified)

    assert committed.verified_receipt_persisted is True
    assert committed.raw_challenge_persisted is False
    assert sink.record_verification(verified) == committed
    assert sink.get_by_verification_receipt_id(verified.verification_receipt_id) == committed
    assert "challenge-clear-fixture" not in committed.model_dump_json()

    reopened = SQLiteM8FeishuUrlChallengeReceiptSink(
        database,
        BUSY_TIMEOUT_MS,
        SHA_A,
        SHA_B,
        lambda: RECEIVED_AT + timedelta(milliseconds=30),
    )
    assert reopened.get_by_verification_receipt_id(verified.verification_receipt_id) == committed

    with sqlite3.connect(database) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "UPDATE m8_feishu_url_challenge_commits SET committed_at = committed_at"
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM m8_feishu_url_challenge_commits")


def test_challenge_sink_rejects_incomplete_layout(tmp_path: Path) -> None:
    database = tmp_path / "labcourt.sqlite3"
    SQLiteM8FeishuUrlChallengeReceiptSink.initialize(
        database,
        BUSY_TIMEOUT_MS,
        SHA_A,
        SHA_B,
        lambda: RECEIVED_AT + timedelta(milliseconds=20),
    )
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TRIGGER m8_feishu_url_challenge_commits_no_update")

    with pytest.raises(RepositoryIntegrityError, match="layout is incomplete"):
        SQLiteM8FeishuUrlChallengeReceiptSink(
            database,
            BUSY_TIMEOUT_MS,
            SHA_A,
            SHA_B,
            lambda: RECEIVED_AT + timedelta(milliseconds=20),
        )
