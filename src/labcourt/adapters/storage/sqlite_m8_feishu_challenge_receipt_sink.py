"""Append-only SQLite audit sink for verified Feishu URL challenges."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path

from pydantic import ValidationError

from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_feishu_challenge import (
    M8FeishuUrlChallengeCommitReceiptV1,
    M8FeishuUrlChallengeVerificationReceiptV1,
)
from labcourt.exceptions import ConcurrentModification, ContractViolation, EvidenceMissing

from .sqlite_m8_feishu_inbound_repository import SQLiteM8FeishuInboundRepository
from .sqlite_m8_operations_repository import M8_MIGRATIONS
from .sqlite_repository import (
    MigrationRunner,
    RepositoryIntegrityError,
    _is_sqlite_concurrency_error,
    _open_connection,
    _row_str,
    _validate_busy_timeout,
)

_REQUIRED_OBJECTS = frozenset(
    {
        "m8_feishu_url_challenge_commits",
        "idx_m8_feishu_url_challenge_commits_profile",
        "m8_feishu_url_challenge_commits_no_update",
        "m8_feishu_url_challenge_commits_no_delete",
        "m8_feishu_url_challenge_commits_no_replace",
    }
)


def _validate_sha256(value: str, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"M8 Feishu URL challenge {name} must be lowercase SHA-256 hex")
    return value


def _require_utc(value: datetime, name: str) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
    ):
        raise ValueError(f"M8 Feishu URL challenge {name} must be timezone-aware UTC")
    return value


def _canonical_utc(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


class SQLiteM8FeishuUrlChallengeReceiptSink:
    """Persist hash-only challenge receipts before the exact response is written."""

    def __init__(
        self,
        database_path: str | Path,
        busy_timeout_ms: int,
        repository_manifest_id: Sha256Hex,
        commit_manifest_id: Sha256Hex,
        clock: Callable[[], datetime],
    ) -> None:
        self._challenge_commit_manifest_id = _validate_sha256(
            commit_manifest_id,
            "commit manifest",
        )
        if not callable(clock):
            raise TypeError("M8 Feishu URL challenge sink requires a clock")
        self._challenge_clock = clock
        self._database_path = Path(database_path)
        self._busy_timeout_ms = _validate_busy_timeout(busy_timeout_ms)
        self._repository_manifest_id = _validate_sha256(
            repository_manifest_id,
            "repository manifest",
        )
        with self._read() as connection:
            self._require_schema(connection)

    @classmethod
    def initialize(
        cls,
        database_path: str | Path,
        busy_timeout_ms: int,
        repository_manifest_id: Sha256Hex,
        commit_manifest_id: Sha256Hex,
        clock: Callable[[], datetime],
    ) -> SQLiteM8FeishuUrlChallengeReceiptSink:
        MigrationRunner(database_path, busy_timeout_ms, M8_MIGRATIONS).apply_all()
        return cls(
            database_path,
            busy_timeout_ms,
            repository_manifest_id,
            commit_manifest_id,
            clock,
        )

    @contextmanager
    def _read(self) -> Iterator[sqlite3.Connection]:
        connection = _open_connection(
            self._database_path,
            self._busy_timeout_ms,
            allow_create=False,
        )
        try:
            connection.execute("BEGIN")
            yield connection
            connection.commit()
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    @contextmanager
    def _immediate(self) -> Iterator[sqlite3.Connection]:
        connection: sqlite3.Connection | None = None
        try:
            connection = _open_connection(
                self._database_path,
                self._busy_timeout_ms,
                allow_create=False,
            )
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except BaseException as error:
            if connection is not None and connection.in_transaction:
                connection.rollback()
            if isinstance(error, sqlite3.OperationalError) and _is_sqlite_concurrency_error(
                error
            ):
                raise ConcurrentModification(
                    "M8 Feishu URL challenge SQLite writer lock could not be acquired"
                ) from error
            raise
        finally:
            if connection is not None:
                connection.close()

    @staticmethod
    def _require_schema(connection: sqlite3.Connection) -> None:
        SQLiteM8FeishuInboundRepository._require_schema(connection)
        try:
            migration = connection.execute(
                "SELECT name FROM schema_migrations WHERE version = 12"
            ).fetchone()
        except sqlite3.DatabaseError as error:
            raise RepositoryIntegrityError(
                "M8 Feishu URL challenge migration ledger is invalid"
            ) from error
        if migration is None or _row_str(migration, "name") != "m8_feishu_url_challenge_audit":
            raise RepositoryIntegrityError(
                "M8 Feishu URL challenge migration 0012 is absent"
            )
        observed = {
            _row_str(row, "name")
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE name IN ({})".format(
                    ",".join("?" for _name in _REQUIRED_OBJECTS)
                ),
                tuple(sorted(_REQUIRED_OBJECTS)),
            ).fetchall()
        }
        if observed != _REQUIRED_OBJECTS:
            raise RepositoryIntegrityError(
                "M8 Feishu URL challenge audit layout is incomplete"
            )

    def record_verification(
        self,
        receipt: M8FeishuUrlChallengeVerificationReceiptV1,
    ) -> M8FeishuUrlChallengeCommitReceiptV1:
        if not isinstance(receipt, M8FeishuUrlChallengeVerificationReceiptV1):
            raise TypeError("M8 Feishu URL challenge sink requires a typed receipt")
        with self._immediate() as connection:
            existing_row = connection.execute(
                """
                SELECT * FROM m8_feishu_url_challenge_commits
                WHERE verification_receipt_id = ?
                """,
                (receipt.verification_receipt_id,),
            ).fetchone()
            if existing_row is not None:
                existing = self._load_challenge_commit(existing_row)
                if (
                    existing.verification_receipt == receipt
                    and existing.commit_manifest_id
                    == self._challenge_commit_manifest_id
                ):
                    return existing
                raise ConcurrentModification(
                    "M8 Feishu URL challenge audit retry conflicts"
                )
            committed_at = _require_utc(self._challenge_clock(), "commit time")
            try:
                commit = M8FeishuUrlChallengeCommitReceiptV1(
                    verification_receipt=receipt,
                    committed_at=committed_at,
                    commit_manifest_id=self._challenge_commit_manifest_id,
                    repository_manifest_id=self._repository_manifest_id,
                )
            except ValidationError as error:
                raise ContractViolation(
                    "M8 Feishu URL challenge audit commit is invalid"
                ) from error
            self._insert_challenge_commit(connection, commit)
            return commit

    def get_by_verification_receipt_id(
        self,
        verification_receipt_id: str,
    ) -> M8FeishuUrlChallengeCommitReceiptV1:
        receipt_id = _validate_sha256(
            verification_receipt_id,
            "verification receipt ID",
        )
        with self._read() as connection:
            row = connection.execute(
                """
                SELECT * FROM m8_feishu_url_challenge_commits
                WHERE verification_receipt_id = ?
                """,
                (receipt_id,),
            ).fetchone()
            if row is None:
                raise EvidenceMissing("M8 Feishu URL challenge audit was not found")
            return self._load_challenge_commit(row)

    def _load_challenge_commit(
        self,
        row: sqlite3.Row,
    ) -> M8FeishuUrlChallengeCommitReceiptV1:
        raw = _row_str(row, "receipt_json")
        try:
            receipt = M8FeishuUrlChallengeCommitReceiptV1.model_validate_json(raw)
        except ValidationError as error:
            raise RepositoryIntegrityError(
                "persisted M8 Feishu URL challenge audit is invalid"
            ) from error
        verified = receipt.verification_receipt
        if (
            canonical_json(receipt.model_dump(mode="json")) != raw
            or receipt.commit_receipt_id != _row_str(row, "commit_receipt_id")
            or verified.verification_receipt_id
            != _row_str(row, "verification_receipt_id")
            or verified.profile.inbound_profile_id != _row_str(row, "inbound_profile_id")
            or verified.ingress_request.ingress_request_id
            != _row_str(row, "ingress_request_id")
            or verified.ingress_request.encrypted_body_sha256
            != _row_str(row, "encrypted_body_sha256")
            or verified.decrypted_challenge_sha256
            != _row_str(row, "decrypted_challenge_sha256")
            or verified.response_document_sha256
            != _row_str(row, "response_document_sha256")
            or _canonical_utc(verified.verified_at) != _row_str(row, "verified_at")
            or _canonical_utc(receipt.committed_at) != _row_str(row, "committed_at")
            or receipt.commit_manifest_id != _row_str(row, "commit_manifest_id")
            or receipt.repository_manifest_id != self._repository_manifest_id
            or receipt.repository_manifest_id != _row_str(row, "repository_manifest_id")
        ):
            raise RepositoryIntegrityError(
                "M8 Feishu URL challenge audit index conflicts with receipt"
            )
        return receipt

    @staticmethod
    def _insert_challenge_commit(
        connection: sqlite3.Connection,
        receipt: M8FeishuUrlChallengeCommitReceiptV1,
    ) -> None:
        verified = receipt.verification_receipt
        try:
            connection.execute(
                """
                INSERT INTO m8_feishu_url_challenge_commits(
                    commit_receipt_id, verification_receipt_id, inbound_profile_id,
                    ingress_request_id, encrypted_body_sha256,
                    decrypted_challenge_sha256, response_document_sha256,
                    verified_at, committed_at, commit_manifest_id,
                    repository_manifest_id, receipt_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    receipt.commit_receipt_id,
                    verified.verification_receipt_id,
                    verified.profile.inbound_profile_id,
                    verified.ingress_request.ingress_request_id,
                    verified.ingress_request.encrypted_body_sha256,
                    verified.decrypted_challenge_sha256,
                    verified.response_document_sha256,
                    _canonical_utc(verified.verified_at),
                    _canonical_utc(receipt.committed_at),
                    receipt.commit_manifest_id,
                    receipt.repository_manifest_id,
                    canonical_json(receipt.model_dump(mode="json")),
                ),
            )
        except sqlite3.IntegrityError as error:
            raise ConcurrentModification(
                "M8 Feishu URL challenge audit append was rejected"
            ) from error


__all__ = ["SQLiteM8FeishuUrlChallengeReceiptSink"]
