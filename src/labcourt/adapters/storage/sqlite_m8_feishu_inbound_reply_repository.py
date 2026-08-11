"""Atomic SQLite mapping from verified Feishu messages to generic notification replies."""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

from pydantic import ValidationError

from labcourt.application.m8_notification_workflow import build_notification_transition_commit
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_feishu_inbound import M8FeishuInboundMessageCommitReceiptV1
from labcourt.contracts.m8_feishu_inbound_reply import (
    M8FeishuInboundReplyCommitReceiptV1,
    M8FeishuInboundReplyCorrelationAuthorityV1,
)
from labcourt.contracts.m8_notification_lifecycle import (
    M8NotificationAction,
    M8NotificationInitiatorKind,
    M8NotificationTransitionCommandV1,
)
from labcourt.contracts.m8_notification_persistence import M8NotificationCommitReceiptV1
from labcourt.contracts.references import require_reference_token
from labcourt.exceptions import ConcurrentModification, EvidenceMissing

from .sqlite_m8_notification_repository import (
    SQLiteM8NotificationRepository,
    _validate_sha256,
)
from .sqlite_repository import RepositoryIntegrityError, _row_int, _row_str

_PROVIDER_RECEIPT_JSON_PATH = (
    "$.audit_event.transition_command.dispatch_result.provider_receipt_id"
)
_ADAPTER_ID_JSON_PATH = (
    "$.audit_event.transition_command.dispatch_result.request.channel_capability.adapter_id"
)
_REQUIRED_OBJECTS = frozenset(
    {
        "idx_m8_notification_provider_receipt",
        "m8_feishu_inbound_reply_commits",
        "idx_m8_feishu_inbound_replies_notification",
        "m8_feishu_inbound_reply_commits_no_update",
        "m8_feishu_inbound_reply_commits_no_delete",
        "m8_feishu_inbound_reply_commits_no_replace",
    }
)


class SQLiteM8FeishuInboundReplyRepository(SQLiteM8NotificationRepository):
    """Commit one verified reply and notification transition in one writer transaction."""

    def __init__(
        self,
        database_path: str | Path,
        busy_timeout_ms: int,
        repository_manifest_id: Sha256Hex,
    ) -> None:
        super().__init__(database_path, busy_timeout_ms, repository_manifest_id)

    @classmethod
    def initialize(
        cls,
        database_path: str | Path,
        busy_timeout_ms: int,
        repository_manifest_id: Sha256Hex,
    ) -> SQLiteM8FeishuInboundReplyRepository:
        repository = super().initialize(
            database_path,
            busy_timeout_ms,
            repository_manifest_id,
        )
        if not isinstance(repository, cls):
            raise RepositoryIntegrityError("M8 Feishu reply repository initialization failed")
        return repository

    @staticmethod
    def _require_schema(connection: sqlite3.Connection) -> None:
        SQLiteM8NotificationRepository._require_schema(connection)
        try:
            migrations = connection.execute(
                "SELECT version, name FROM schema_migrations WHERE version IN (9, 10) "
                "ORDER BY version"
            ).fetchall()
        except sqlite3.DatabaseError as error:
            raise RepositoryIntegrityError(
                "M8 Feishu reply migration ledger is invalid"
            ) from error
        observed_migrations = tuple(
            (_row_int(row, "version"), _row_str(row, "name")) for row in migrations
        )
        if observed_migrations != (
            (9, "m8_feishu_inbound_messages"),
            (10, "m8_feishu_inbound_replies"),
        ):
            raise RepositoryIntegrityError("M8 Feishu reply migrations 0009-0010 are absent")
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
            raise RepositoryIntegrityError("M8 Feishu reply persistence layout is incomplete")

    def get_notification_chain_by_provider_message_id(
        self,
        provider_message_id: str,
        adapter_id: str,
    ) -> tuple[M8NotificationCommitReceiptV1, ...]:
        message_id = require_reference_token(
            provider_message_id,
            "M8 Feishu outbound provider message ID",
        )
        adapter = require_reference_token(adapter_id, "M8 Feishu outbound adapter ID")
        with self._read() as connection:
            return self._load_notification_chain(connection, message_id, adapter)

    def get_reply_by_provider_message_id(
        self,
        provider_message_id: str,
    ) -> M8FeishuInboundReplyCommitReceiptV1:
        message_id = require_reference_token(
            provider_message_id,
            "M8 Feishu inbound provider message ID",
        )
        with self._read() as connection:
            row = connection.execute(
                "SELECT * FROM m8_feishu_inbound_reply_commits "
                "WHERE provider_message_id = ?",
                (message_id,),
            ).fetchone()
            if row is None:
                raise EvidenceMissing("M8 Feishu inbound reply commit was not found")
            return self._load_reply_row(connection, row)

    def commit_reply(
        self,
        correlation_authority: M8FeishuInboundReplyCorrelationAuthorityV1,
        notification_raw_storage_manifest_id: str,
        notification_audit_manifest_id: str,
        transition_command_manifest_id: str,
        reply_commit_manifest_id: str,
    ) -> M8FeishuInboundReplyCommitReceiptV1:
        if not isinstance(
            correlation_authority,
            M8FeishuInboundReplyCorrelationAuthorityV1,
        ):
            raise TypeError("M8 Feishu reply commit requires a typed correlation authority")
        raw_manifest = _validate_sha256(
            notification_raw_storage_manifest_id,
            "Feishu reply raw storage manifest",
        )
        audit_manifest = _validate_sha256(
            notification_audit_manifest_id,
            "Feishu reply audit manifest",
        )
        command_manifest = _validate_sha256(
            transition_command_manifest_id,
            "Feishu reply transition command manifest",
        )
        commit_manifest = _validate_sha256(
            reply_commit_manifest_id,
            "Feishu reply commit manifest",
        )
        with self._immediate() as connection:
            retry_row = connection.execute(
                "SELECT * FROM m8_feishu_inbound_reply_commits "
                "WHERE provider_message_id = ?",
                (correlation_authority.provider_message_id,),
            ).fetchone()
            if retry_row is not None:
                existing = self._load_reply_row(connection, retry_row)
                self._verify_exact_retry(
                    existing,
                    correlation_authority,
                    raw_manifest,
                    audit_manifest,
                    command_manifest,
                    commit_manifest,
                )
                return existing

            inbound = self._load_inbound_commit(
                connection,
                correlation_authority.provider_message_id,
            )
            if inbound != correlation_authority.inbound_commit:
                raise ConcurrentModification("M8 Feishu reply inbound authority is stale")
            raw_reply = self._load_inbound_content(connection, inbound)

            persisted_chain = self._load_notification_chain(
                connection,
                correlation_authority.reply_correlation_message_id,
                (
                    correlation_authority.inbound_commit.verification_receipt.profile
                    .outbound_profile.candidate.adapter_id
                ),
            )
            if persisted_chain != correlation_authority.notification_commit_chain:
                raise ConcurrentModification("M8 Feishu reply notification history is stale")
            before = self._load_current_notification_for_write(
                connection,
                correlation_authority.notification_id,
            )
            if before != correlation_authority.notification_commit_chain[-1]:
                raise ConcurrentModification("M8 Feishu reply notification source is stale")
            target = self._load_current_target(
                connection,
                correlation_authority.actor_id,
                correlation_authority.reply.channel,
            )
            if target != correlation_authority.current_target_receipt:
                raise ConcurrentModification("M8 Feishu reply target authority is stale")
            actor = self._load_current_actor(connection, correlation_authority.actor_id)
            if actor != correlation_authority.current_actor_receipt:
                raise ConcurrentModification("M8 Feishu reply actor authority is stale")

            command = M8NotificationTransitionCommandV1(
                notification_id=before.notification_id,
                source_notification_version=before.notification_version,
                source_notification_authority_sha256=before.notification_document_sha256,
                source_status=before.status,
                action=M8NotificationAction.RESPOND,
                initiator_kind=M8NotificationInitiatorKind.ACTOR,
                actor_authority=actor.authority,
                reply=correlation_authority.reply,
                supporting_authorities=(correlation_authority.supporting_authority(),),
                explicit_human_confirmation=True,
                occurred_at=correlation_authority.correlated_at,
                command_manifest_id=command_manifest,
            )
            try:
                notification_commit = build_notification_transition_commit(
                    before,
                    command,
                    (raw_reply,),
                    raw_manifest,
                    actor,
                    audit_manifest,
                    self._repository_manifest_id,
                )
                candidate = M8FeishuInboundReplyCommitReceiptV1(
                    correlation_authority=correlation_authority,
                    notification_commit=notification_commit,
                    reply_commit_manifest_id=commit_manifest,
                )
            except ValueError as error:
                raise ConcurrentModification(str(error)) from error
            self._insert_or_verify_raw(
                connection,
                notification_commit.raw_artifact_receipts[0],
                raw_reply,
            )
            self._insert_notification(connection, notification_commit)
            self._insert_reply(connection, candidate)
            return candidate

    def _load_notification_chain(
        self,
        connection: sqlite3.Connection,
        provider_message_id: str,
        adapter_id: str,
    ) -> tuple[M8NotificationCommitReceiptV1, ...]:
        outbound_row = connection.execute(
            "SELECT * FROM m8_notification_versions WHERE status = 'SENT' "
            "AND target_channel = 'FEISHU' "
            "AND json_extract(commit_receipt_json, ?) = ? "
            "AND json_extract(commit_receipt_json, ?) = ?",
            (
                _PROVIDER_RECEIPT_JSON_PATH,
                provider_message_id,
                _ADAPTER_ID_JSON_PATH,
                adapter_id,
            ),
        ).fetchone()
        if outbound_row is None:
            raise EvidenceMissing("M8 Feishu outbound provider message was not found")
        outbound = self._load_notification_row(connection, outbound_row)
        rows = connection.execute(
            "SELECT * FROM m8_notification_versions WHERE notification_id = ? "
            "AND notification_version >= ? ORDER BY notification_version",
            (outbound.notification_id, outbound.notification_version),
        ).fetchall()
        chain = tuple(self._load_notification_row(connection, row) for row in rows)
        if not chain or chain[0] != outbound:
            raise RepositoryIntegrityError("M8 Feishu outbound notification chain is incomplete")
        return chain

    def _load_inbound_commit(
        self,
        connection: sqlite3.Connection,
        provider_message_id: str,
    ) -> M8FeishuInboundMessageCommitReceiptV1:
        row = connection.execute(
            "SELECT * FROM m8_feishu_inbound_message_commits WHERE provider_message_id = ?",
            (provider_message_id,),
        ).fetchone()
        if row is None:
            raise EvidenceMissing("M8 Feishu inbound provider message was not found")
        raw_json = _row_str(row, "receipt_json")
        try:
            receipt = M8FeishuInboundMessageCommitReceiptV1.model_validate_json(raw_json)
        except ValidationError as error:
            raise RepositoryIntegrityError(
                "persisted M8 Feishu inbound authority is invalid"
            ) from error
        if (
            canonical_json(receipt.model_dump(mode="json")) != raw_json
            or receipt.provider_message_id != _row_str(row, "provider_message_id")
            or receipt.commit_receipt_id != _row_str(row, "commit_receipt_id")
            or receipt.repository_manifest_id != self._repository_manifest_id
            or receipt.repository_manifest_id != _row_str(row, "repository_manifest_id")
        ):
            raise RepositoryIntegrityError("M8 Feishu inbound authority index conflicts")
        return receipt

    def _load_inbound_content(
        self,
        connection: sqlite3.Connection,
        inbound: M8FeishuInboundMessageCommitReceiptV1,
    ) -> bytes:
        verified = inbound.verification_receipt
        row = connection.execute(
            "SELECT * FROM m8_feishu_inbound_raw_artifacts WHERE raw_artifact_ref = ?",
            (verified.content_document_ref,),
        ).fetchone()
        if row is None:
            raise RepositoryIntegrityError("M8 Feishu inbound reply content is missing")
        value = row["raw_bytes"]
        if not isinstance(value, bytes):
            raise RepositoryIntegrityError("M8 Feishu inbound reply content is not bytes")
        if (
            _row_str(row, "commit_receipt_id") != inbound.commit_receipt_id
            or _row_int(row, "artifact_ordinal") != 2
            or _row_str(row, "raw_artifact_ref") != verified.content_document_ref
            or _row_str(row, "raw_artifact_sha256") != verified.content_document_sha256
            or _row_int(row, "raw_artifact_size_bytes") != verified.content_size_bytes
            or hashlib.sha256(value).hexdigest() != verified.content_document_sha256
            or _row_str(row, "repository_manifest_id") != self._repository_manifest_id
        ):
            raise RepositoryIntegrityError("M8 Feishu inbound reply content is invalid")
        return value

    def _load_reply_row(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> M8FeishuInboundReplyCommitReceiptV1:
        raw_json = _row_str(row, "receipt_json")
        try:
            receipt = M8FeishuInboundReplyCommitReceiptV1.model_validate_json(raw_json)
        except ValidationError as error:
            raise RepositoryIntegrityError(
                "persisted M8 Feishu reply commit is invalid"
            ) from error
        correlation = receipt.correlation_authority
        command = receipt.notification_commit.audit_event.transition_command
        if command is None or command.reply is None:
            raise RepositoryIntegrityError("persisted M8 Feishu reply command is incomplete")
        if (
            canonical_json(receipt.model_dump(mode="json")) != raw_json
            or receipt.commit_receipt_id != _row_str(row, "commit_receipt_id")
            or receipt.provider_message_deduplication_key
            != _row_str(row, "provider_message_id")
            or correlation.correlation_authority_id
            != _row_str(row, "correlation_authority_id")
            or correlation.correlation_authority_document_sha256
            != _row_str(row, "correlation_authority_document_sha256")
            or correlation.inbound_commit.commit_receipt_id
            != _row_str(row, "inbound_commit_receipt_id")
            or correlation.reply_correlation_message_id
            != _row_str(row, "outbound_provider_message_id")
            or receipt.notification_commit.notification_id
            != _row_str(row, "notification_id")
            or correlation.notification_commit_chain[-1].notification_version
            != _row_int(row, "source_notification_version")
            or receipt.notification_commit.notification_version
            != _row_int(row, "notification_version")
            or receipt.notification_commit.commit_receipt_id
            != _row_str(row, "notification_commit_receipt_id")
            or command.reply.reply_authority_id != _row_str(row, "reply_authority_id")
            or receipt.reply_commit_manifest_id != _row_str(row, "reply_commit_manifest_id")
            or receipt.notification_commit.repository_manifest_id
            != self._repository_manifest_id
            or _row_str(row, "repository_manifest_id") != self._repository_manifest_id
        ):
            raise RepositoryIntegrityError("M8 Feishu reply commit index conflicts")
        notification_row = connection.execute(
            "SELECT * FROM m8_notification_versions WHERE notification_id = ? "
            "AND notification_version = ?",
            (
                receipt.notification_commit.notification_id,
                receipt.notification_commit.notification_version,
            ),
        ).fetchone()
        if (
            notification_row is None
            or self._load_notification_row(connection, notification_row)
            != receipt.notification_commit
        ):
            raise RepositoryIntegrityError("M8 Feishu reply notification commit is missing")
        return receipt

    @staticmethod
    def _verify_exact_retry(
        existing: M8FeishuInboundReplyCommitReceiptV1,
        correlation: M8FeishuInboundReplyCorrelationAuthorityV1,
        raw_manifest: str,
        audit_manifest: str,
        command_manifest: str,
        commit_manifest: str,
    ) -> None:
        command = existing.notification_commit.audit_event.transition_command
        raw_receipts = existing.notification_commit.raw_artifact_receipts
        if (
            existing.correlation_authority != correlation
            or existing.reply_commit_manifest_id != commit_manifest
            or command is None
            or command.command_manifest_id != command_manifest
            or existing.notification_commit.audit_event.audit_manifest_id != audit_manifest
            or len(raw_receipts) != 1
            or raw_receipts[0].raw_storage_manifest_id != raw_manifest
        ):
            raise ConcurrentModification(
                "M8 Feishu inbound reply was already committed differently"
            )

    def _insert_reply(
        self,
        connection: sqlite3.Connection,
        receipt: M8FeishuInboundReplyCommitReceiptV1,
    ) -> None:
        correlation = receipt.correlation_authority
        command = receipt.notification_commit.audit_event.transition_command
        if command is None or command.reply is None:
            raise RepositoryIntegrityError("M8 Feishu reply insert lacks reply authority")
        try:
            connection.execute(
                """
                INSERT INTO m8_feishu_inbound_reply_commits(
                    commit_receipt_id, provider_message_id, correlation_authority_id,
                    correlation_authority_document_sha256, inbound_commit_receipt_id,
                    outbound_provider_message_id, notification_id,
                    source_notification_version, notification_version,
                    notification_commit_receipt_id, reply_authority_id,
                    reply_commit_manifest_id, repository_manifest_id, receipt_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    receipt.commit_receipt_id,
                    receipt.provider_message_deduplication_key,
                    correlation.correlation_authority_id,
                    correlation.correlation_authority_document_sha256,
                    correlation.inbound_commit.commit_receipt_id,
                    correlation.reply_correlation_message_id,
                    receipt.notification_commit.notification_id,
                    correlation.notification_commit_chain[-1].notification_version,
                    receipt.notification_commit.notification_version,
                    receipt.notification_commit.commit_receipt_id,
                    command.reply.reply_authority_id,
                    receipt.reply_commit_manifest_id,
                    self._repository_manifest_id,
                    canonical_json(receipt.model_dump(mode="json")),
                ),
            )
        except sqlite3.IntegrityError as error:
            raise ConcurrentModification("M8 Feishu inbound reply append was rejected") from error


__all__ = ["SQLiteM8FeishuInboundReplyRepository"]
