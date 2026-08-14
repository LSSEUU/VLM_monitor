"""Append-only SQLite persistence for M8 Agent conversations and model calls."""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from uuid import uuid4

from pydantic import ValidationError

from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_agent_chat import (
    M8AgentConversationRemovalReceiptV1,
    M8AgentConversationSummaryV1,
    M8AgentConversationTurnV1,
    M8AgentConversationV1,
    M8AgentFailureCode,
    M8AgentModelCallReceiptV1,
    M8AgentTurnCompletionV1,
    M8AgentTurnState,
)
from labcourt.contracts.m8_case_persistence import M8ActorAuthorityCommitReceiptV1
from labcourt.ports.m8_agent_chat import (
    M8AgentConversationRepositoryError,
)

from .sqlite_m8_operations_repository import M8_MIGRATIONS
from .sqlite_repository import (
    MigrationRunner,
    RepositoryIntegrityError,
    _is_sqlite_concurrency_error,
    _open_connection,
    _row_int,
    _row_str,
    _validate_busy_timeout,
)

_REQUIRED_OBJECTS = frozenset(
    {
        "m8_agent_conversations",
        "idx_m8_agent_conversations_actor",
        "m8_agent_turn_events",
        "idx_m8_agent_turn_events_conversation",
        "m8_agent_raw_responses",
        "idx_m8_agent_raw_responses_turn",
        "m8_agent_cache_entries",
        "idx_m8_agent_cache_entries_actor",
        "m8_agent_conversation_removals",
        "idx_m8_agent_conversation_removals_actor",
        "m8_agent_conversations_no_update",
        "m8_agent_conversations_no_delete",
        "m8_agent_conversations_no_replace",
        "m8_agent_turn_events_validate_sequence",
        "m8_agent_turn_events_no_update",
        "m8_agent_turn_events_no_delete",
        "m8_agent_turn_events_no_replace",
        "m8_agent_raw_responses_no_update",
        "m8_agent_raw_responses_no_delete",
        "m8_agent_raw_responses_no_replace",
        "m8_agent_cache_entries_no_update",
        "m8_agent_cache_entries_no_delete",
        "m8_agent_cache_entries_no_replace",
        "m8_agent_conversation_removals_no_update",
        "m8_agent_conversation_removals_no_delete",
        "m8_agent_conversation_removals_no_replace",
    }
)


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("M8 Agent clock must return an aware datetime")
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("persisted M8 Agent timestamp is not aware")
    return parsed.astimezone(UTC)


def _validate_sha256(value: str, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"M8 Agent {name} must be lowercase SHA-256 hex")
    return value


class SQLiteM8AgentConversationRepository:
    """Persist conversations as immutable acceptance and terminal events."""

    def __init__(
        self,
        database_path: str | Path,
        busy_timeout_ms: int,
        repository_manifest_id: Sha256Hex,
        clock: Callable[[], datetime],
    ) -> None:
        self._database_path = Path(database_path)
        self._busy_timeout_ms = _validate_busy_timeout(busy_timeout_ms)
        self._repository_manifest_id = _validate_sha256(
            repository_manifest_id, "repository manifest"
        )
        if not callable(clock):
            raise TypeError("M8 Agent repository clock must be callable")
        self._clock = clock
        with self._read() as connection:
            self._require_schema(connection)

    @classmethod
    def initialize(
        cls,
        database_path: str | Path,
        busy_timeout_ms: int,
        repository_manifest_id: Sha256Hex,
        clock: Callable[[], datetime],
    ) -> SQLiteM8AgentConversationRepository:
        MigrationRunner(database_path, busy_timeout_ms, M8_MIGRATIONS).apply_all()
        return cls(database_path, busy_timeout_ms, repository_manifest_id, clock)

    @contextmanager
    def _read(self) -> Iterator[sqlite3.Connection]:
        connection = _open_connection(
            self._database_path, self._busy_timeout_ms, allow_create=False
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
                self._database_path, self._busy_timeout_ms, allow_create=False
            )
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except BaseException as error:
            if connection is not None and connection.in_transaction:
                connection.rollback()
            if isinstance(error, sqlite3.OperationalError) and _is_sqlite_concurrency_error(error):
                raise M8AgentConversationRepositoryError(
                    M8AgentFailureCode.STREAM_INTERRUPTED
                ) from error
            raise
        finally:
            if connection is not None:
                connection.close()

    @staticmethod
    def _require_schema(connection: sqlite3.Connection) -> None:
        try:
            migration = connection.execute(
                "SELECT name FROM schema_migrations WHERE version = 14"
            ).fetchone()
        except sqlite3.DatabaseError as error:
            raise RepositoryIntegrityError("M8 Agent migration ledger is invalid") from error
        if migration is None or _row_str(migration, "name") != "m8_agent_conversation_removals":
            raise RepositoryIntegrityError("M8 Agent migration 0014 is not installed")
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
            raise RepositoryIntegrityError("M8 Agent persistence layout is incomplete")

    def create_conversation(
        self,
        actor_receipt: M8ActorAuthorityCommitReceiptV1,
    ) -> M8AgentConversationSummaryV1:
        self._require_active_actor(actor_receipt)
        now = self._clock()
        conversation_id = sha256_hex(
            [
                "m8-agent-conversation",
                1,
                actor_receipt.authority.actor_id,
                actor_receipt.commit_receipt_id,
                _utc_text(now),
                uuid4().hex,
            ]
        )
        with self._immediate() as connection:
            connection.execute(
                """
                INSERT INTO m8_agent_conversations(
                    conversation_id, actor_id, actor_role,
                    actor_authority_commit_receipt_id, created_at,
                    repository_manifest_id
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    conversation_id,
                    actor_receipt.authority.actor_id,
                    actor_receipt.authority.role.value,
                    actor_receipt.commit_receipt_id,
                    _utc_text(now),
                    self._repository_manifest_id,
                ),
            )
        return M8AgentConversationSummaryV1(
            conversation_id=conversation_id,
            actor_id=actor_receipt.authority.actor_id,
            actor_role=actor_receipt.authority.role,
            actor_authority_commit_receipt_id=actor_receipt.commit_receipt_id,
            created_at=now,
            title="新对话",
            turn_count=0,
            latest_activity_at=now,
            sealed=False,
        )

    def list_conversations(
        self,
        actor_receipt: M8ActorAuthorityCommitReceiptV1,
    ) -> tuple[M8AgentConversationSummaryV1, ...]:
        self._require_active_actor(actor_receipt)
        with self._read() as connection:
            rows = connection.execute(
                """
                SELECT * FROM m8_agent_conversations
                WHERE actor_id = ?
                  AND NOT EXISTS (
                      SELECT 1 FROM m8_agent_conversation_removals AS removal
                      WHERE removal.conversation_id = m8_agent_conversations.conversation_id
                  )
                ORDER BY created_at DESC, conversation_id DESC LIMIT 100
                """,
                (actor_receipt.authority.actor_id,),
            ).fetchall()
            return tuple(self._summary(connection, row, actor_receipt) for row in rows)

    def get_conversation(
        self,
        actor_receipt: M8ActorAuthorityCommitReceiptV1,
        conversation_id: str,
    ) -> M8AgentConversationV1:
        self._require_active_actor(actor_receipt)
        with self._read() as connection:
            row = self._conversation_row(connection, conversation_id)
            self._require_owner(row, actor_receipt, allow_sealed=False)
            summary = self._summary(connection, row, actor_receipt)
            turns = self._turns(connection, conversation_id)
            return M8AgentConversationV1(summary=summary, turns=turns)

    def remove_conversation(
        self,
        actor_receipt: M8ActorAuthorityCommitReceiptV1,
        conversation_id: str,
    ) -> M8AgentConversationRemovalReceiptV1:
        self._require_active_actor(actor_receipt)
        removed_at = self._clock()
        removal_receipt_id = sha256_hex(
            [
                "m8-agent-conversation-removal",
                1,
                conversation_id,
                actor_receipt.authority.actor_id,
                actor_receipt.commit_receipt_id,
                _utc_text(removed_at),
                uuid4().hex,
            ]
        )
        receipt = M8AgentConversationRemovalReceiptV1(
            removal_receipt_id=removal_receipt_id,
            conversation_id=conversation_id,
            actor_id=actor_receipt.authority.actor_id,
            actor_authority_commit_receipt_id=actor_receipt.commit_receipt_id,
            removed_at=removed_at,
        )
        with self._immediate() as connection:
            row = self._conversation_row(connection, conversation_id)
            self._require_owner(row, actor_receipt, allow_sealed=True)
            connection.execute(
                """
                INSERT INTO m8_agent_conversation_removals(
                    removal_receipt_id, conversation_id, actor_id,
                    actor_authority_commit_receipt_id, removed_at,
                    repository_manifest_id
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    receipt.removal_receipt_id,
                    receipt.conversation_id,
                    receipt.actor_id,
                    receipt.actor_authority_commit_receipt_id,
                    _utc_text(receipt.removed_at),
                    self._repository_manifest_id,
                ),
            )
        return receipt

    def begin_turn(
        self,
        actor_receipt: M8ActorAuthorityCommitReceiptV1,
        conversation_id: str,
        query: str,
    ) -> M8AgentConversationTurnV1:
        self._require_active_actor(actor_receipt)
        now = self._clock()
        turn_id = sha256_hex(
            [
                "m8-agent-turn",
                1,
                conversation_id,
                actor_receipt.commit_receipt_id,
                query,
                _utc_text(now),
                uuid4().hex,
            ]
        )
        event = M8AgentConversationTurnV1(
            turn_id=turn_id,
            user_text=query,
            submitted_at=now,
            state=M8AgentTurnState.ACCEPTED,
        )
        with self._immediate() as connection:
            row = self._conversation_row(connection, conversation_id)
            self._require_owner(row, actor_receipt, allow_sealed=False)
            self._insert_event(connection, conversation_id, event, 1, "ACCEPTED", now)
        return event

    def complete_turn(
        self,
        actor_receipt: M8ActorAuthorityCommitReceiptV1,
        completion: M8AgentTurnCompletionV1,
        raw_responses: tuple[tuple[M8AgentModelCallReceiptV1, bytes], ...],
        cache_key: str | None,
    ) -> M8AgentConversationTurnV1:
        self._require_active_actor(actor_receipt)
        with self._immediate() as connection:
            row = self._conversation_row(connection, completion.conversation_id)
            self._require_owner(row, actor_receipt, allow_sealed=False)
            accepted = self._accepted_turn(
                connection, completion.conversation_id, completion.turn_id
            )
            event = M8AgentConversationTurnV1(
                turn_id=completion.turn_id,
                user_text=accepted.user_text,
                submitted_at=accepted.submitted_at,
                state=M8AgentTurnState.COMPLETED,
                completion=completion,
            )
            self._insert_raw_responses(
                connection,
                completion.conversation_id,
                completion.turn_id,
                raw_responses,
            )
            self._insert_event(
                connection,
                completion.conversation_id,
                event,
                2,
                "COMPLETED",
                completion.completed_at,
            )
            if cache_key is not None:
                _validate_sha256(cache_key, "cache key")
                document = canonical_json(completion.model_dump(mode="json"))
                existing = connection.execute(
                    "SELECT completion_json FROM m8_agent_cache_entries WHERE cache_key = ?",
                    (cache_key,),
                ).fetchone()
                if existing is None:
                    connection.execute(
                        """
                        INSERT INTO m8_agent_cache_entries(
                            cache_key, actor_authority_commit_receipt_id,
                            source_conversation_id, source_turn_id, completion_json,
                            completion_sha256, created_at, repository_manifest_id
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            cache_key,
                            actor_receipt.commit_receipt_id,
                            completion.conversation_id,
                            completion.turn_id,
                            document,
                            hashlib.sha256(document.encode("utf-8")).hexdigest(),
                            _utc_text(completion.completed_at),
                            self._repository_manifest_id,
                        ),
                    )
                elif _row_str(existing, "completion_json") != document:
                    raise ValueError("M8 Agent cache key conflicts with persisted completion")
        return event

    def fail_turn(
        self,
        actor_receipt: M8ActorAuthorityCommitReceiptV1,
        conversation_id: str,
        turn_id: str,
        failure_code: M8AgentFailureCode,
        raw_responses: tuple[tuple[M8AgentModelCallReceiptV1, bytes], ...] = (),
    ) -> M8AgentConversationTurnV1:
        self._require_active_actor(actor_receipt)
        now = self._clock()
        with self._immediate() as connection:
            row = self._conversation_row(connection, conversation_id)
            self._require_owner(row, actor_receipt, allow_sealed=False)
            accepted = self._accepted_turn(connection, conversation_id, turn_id)
            event = M8AgentConversationTurnV1(
                turn_id=turn_id,
                user_text=accepted.user_text,
                submitted_at=accepted.submitted_at,
                state=M8AgentTurnState.FAILED,
                failure_code=failure_code,
            )
            self._insert_raw_responses(
                connection,
                conversation_id,
                turn_id,
                raw_responses,
            )
            self._insert_event(connection, conversation_id, event, 2, "FAILED", now)
            return event

    def read_cache(
        self,
        actor_receipt: M8ActorAuthorityCommitReceiptV1,
        cache_key: str,
    ) -> M8AgentTurnCompletionV1 | None:
        self._require_active_actor(actor_receipt)
        _validate_sha256(cache_key, "cache key")
        with self._read() as connection:
            row = connection.execute(
                """
                SELECT * FROM m8_agent_cache_entries
                WHERE cache_key = ? AND actor_authority_commit_receipt_id = ?
                """,
                (cache_key, actor_receipt.commit_receipt_id),
            ).fetchone()
            if row is None:
                return None
            document = _row_str(row, "completion_json")
            if hashlib.sha256(document.encode("utf-8")).hexdigest() != _row_str(
                row, "completion_sha256"
            ):
                raise RepositoryIntegrityError("M8 Agent cache content hash mismatch")
            try:
                return M8AgentTurnCompletionV1.model_validate_json(document)
            except ValidationError as error:
                raise RepositoryIntegrityError("M8 Agent cache contract is invalid") from error

    def last_model_call(
        self,
        actor_receipt: M8ActorAuthorityCommitReceiptV1,
    ) -> M8AgentModelCallReceiptV1 | None:
        self._require_active_actor(actor_receipt)
        with self._read() as connection:
            row = connection.execute(
                """
                SELECT raw.receipt_json FROM m8_agent_raw_responses AS raw
                JOIN m8_agent_conversations AS conversation
                  ON conversation.conversation_id = raw.conversation_id
                WHERE conversation.actor_id = ?
                  AND NOT EXISTS (
                      SELECT 1 FROM m8_agent_conversation_removals AS removal
                      WHERE removal.conversation_id = conversation.conversation_id
                  )
                ORDER BY raw.rowid DESC LIMIT 1
                """,
                (actor_receipt.authority.actor_id,),
            ).fetchone()
            if row is None:
                return None
            try:
                return M8AgentModelCallReceiptV1.model_validate_json(_row_str(row, "receipt_json"))
            except ValidationError as error:
                raise RepositoryIntegrityError("M8 Agent model receipt is invalid") from error

    def _insert_raw_responses(
        self,
        connection: sqlite3.Connection,
        conversation_id: str,
        turn_id: str,
        raw_responses: tuple[tuple[M8AgentModelCallReceiptV1, bytes], ...],
    ) -> None:
        for receipt, raw in raw_responses:
            if hashlib.sha256(raw).hexdigest() != receipt.raw_response_sha256:
                raise ValueError("M8 Agent raw response hash mismatch")
            connection.execute(
                """
                INSERT INTO m8_agent_raw_responses(
                    raw_response_ref, model_call_id, conversation_id, turn_id,
                    round_index, content_sha256, size_bytes, raw_bytes,
                    receipt_json, repository_manifest_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    receipt.raw_response_ref,
                    receipt.model_call_id,
                    conversation_id,
                    turn_id,
                    receipt.round_index,
                    receipt.raw_response_sha256,
                    len(raw),
                    raw,
                    canonical_json(receipt.model_dump(mode="json")),
                    self._repository_manifest_id,
                ),
            )

    @staticmethod
    def _require_active_actor(actor_receipt: M8ActorAuthorityCommitReceiptV1) -> None:
        if not isinstance(actor_receipt, M8ActorAuthorityCommitReceiptV1):
            raise TypeError("M8 Agent repository requires actor receipt")
        if not actor_receipt.authority.active:
            raise M8AgentConversationRepositoryError(M8AgentFailureCode.AUTHORITY_CHANGED)

    @staticmethod
    def _conversation_row(
        connection: sqlite3.Connection,
        conversation_id: str,
    ) -> sqlite3.Row:
        row = cast(
            sqlite3.Row | None,
            connection.execute(
                """
                SELECT * FROM m8_agent_conversations
                WHERE conversation_id = ?
                  AND NOT EXISTS (
                      SELECT 1 FROM m8_agent_conversation_removals AS removal
                      WHERE removal.conversation_id = m8_agent_conversations.conversation_id
                  )
                """,
                (conversation_id,),
            ).fetchone(),
        )
        if row is None:
            raise M8AgentConversationRepositoryError(M8AgentFailureCode.CONVERSATION_NOT_FOUND)
        return row

    @staticmethod
    def _require_owner(
        row: sqlite3.Row,
        actor_receipt: M8ActorAuthorityCommitReceiptV1,
        *,
        allow_sealed: bool,
    ) -> None:
        if _row_str(row, "actor_id") != actor_receipt.authority.actor_id:
            raise M8AgentConversationRepositoryError(M8AgentFailureCode.CONVERSATION_NOT_FOUND)
        sealed = (
            _row_str(row, "actor_authority_commit_receipt_id") != actor_receipt.commit_receipt_id
            or _row_str(row, "actor_role") != actor_receipt.authority.role.value
        )
        if sealed and not allow_sealed:
            raise M8AgentConversationRepositoryError(M8AgentFailureCode.AUTHORITY_CHANGED)

    def _summary(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        actor_receipt: M8ActorAuthorityCommitReceiptV1,
    ) -> M8AgentConversationSummaryV1:
        sealed = (
            _row_str(row, "actor_authority_commit_receipt_id") != actor_receipt.commit_receipt_id
            or _row_str(row, "actor_role") != actor_receipt.authority.role.value
        )
        events = connection.execute(
            """
            SELECT * FROM m8_agent_turn_events
            WHERE conversation_id = ?
            ORDER BY occurred_at, turn_id, event_sequence
            """,
            (_row_str(row, "conversation_id"),),
        ).fetchall()
        accepted = [item for item in events if _row_int(item, "event_sequence") == 1]
        created_at = _parse_utc(_row_str(row, "created_at"))
        title = "历史会话已封存" if sealed else "新对话"
        if accepted and not sealed:
            first = self._load_turn_event(accepted[0])
            title = first.user_text[:32] + ("…" if len(first.user_text) > 32 else "")
        latest = _parse_utc(_row_str(events[-1], "occurred_at")) if events else created_at
        return M8AgentConversationSummaryV1(
            conversation_id=_row_str(row, "conversation_id"),
            actor_id=_row_str(row, "actor_id"),
            actor_role=_row_str(row, "actor_role"),
            actor_authority_commit_receipt_id=_row_str(row, "actor_authority_commit_receipt_id"),
            created_at=created_at,
            title=title,
            turn_count=len(accepted),
            latest_activity_at=latest,
            sealed=sealed,
        )

    def _turns(
        self, connection: sqlite3.Connection, conversation_id: str
    ) -> tuple[M8AgentConversationTurnV1, ...]:
        rows = connection.execute(
            """
            SELECT * FROM m8_agent_turn_events
            WHERE conversation_id = ?
            ORDER BY occurred_at, turn_id, event_sequence
            """,
            (conversation_id,),
        ).fetchall()
        by_turn: dict[str, M8AgentConversationTurnV1] = {}
        order: list[str] = []
        for row in rows:
            event = self._load_turn_event(row)
            if _row_int(row, "event_sequence") == 1:
                order.append(event.turn_id)
            by_turn[event.turn_id] = event
        return tuple(by_turn[turn_id] for turn_id in order)

    def _accepted_turn(
        self,
        connection: sqlite3.Connection,
        conversation_id: str,
        turn_id: str,
    ) -> M8AgentConversationTurnV1:
        terminal = connection.execute(
            """
            SELECT 1 FROM m8_agent_turn_events
            WHERE conversation_id = ? AND turn_id = ? AND event_sequence = 2
            """,
            (conversation_id, turn_id),
        ).fetchone()
        if terminal is not None:
            raise ValueError("M8 Agent turn already has a terminal event")
        row = connection.execute(
            """
            SELECT * FROM m8_agent_turn_events
            WHERE conversation_id = ? AND turn_id = ? AND event_sequence = 1
            """,
            (conversation_id, turn_id),
        ).fetchone()
        if row is None:
            raise M8AgentConversationRepositoryError(M8AgentFailureCode.CONVERSATION_NOT_FOUND)
        return self._load_turn_event(row)

    def _insert_event(
        self,
        connection: sqlite3.Connection,
        conversation_id: str,
        event: M8AgentConversationTurnV1,
        sequence: int,
        kind: str,
        occurred_at: datetime,
    ) -> None:
        document = canonical_json(event.model_dump(mode="json"))
        event_sha256 = hashlib.sha256(document.encode("utf-8")).hexdigest()
        event_id = sha256_hex(
            ["m8-agent-turn-event", 1, conversation_id, event.turn_id, sequence, event_sha256]
        )
        connection.execute(
            """
            INSERT INTO m8_agent_turn_events(
                event_id, conversation_id, turn_id, event_sequence, event_kind,
                occurred_at, event_json, event_sha256, repository_manifest_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                conversation_id,
                event.turn_id,
                sequence,
                kind,
                _utc_text(occurred_at),
                document,
                event_sha256,
                self._repository_manifest_id,
            ),
        )

    @staticmethod
    def _load_turn_event(row: sqlite3.Row) -> M8AgentConversationTurnV1:
        document = _row_str(row, "event_json")
        if hashlib.sha256(document.encode("utf-8")).hexdigest() != _row_str(row, "event_sha256"):
            raise RepositoryIntegrityError("M8 Agent turn event hash mismatch")
        try:
            return M8AgentConversationTurnV1.model_validate_json(document)
        except ValidationError as error:
            raise RepositoryIntegrityError("M8 Agent turn event contract is invalid") from error


__all__ = ["SQLiteM8AgentConversationRepository"]
