"""Append-only SQLite authority for live Feishu workers and shared Agent turns."""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ValidationError

from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_feishu_live import (
    M8FeishuAgentReplyCompletionV1,
    M8FeishuAgentReplyEnvelopeV1,
    M8FeishuAlertBridgeReceiptV1,
    M8FeishuCardActionIntentV1,
    M8FeishuCardActionReceiptV1,
    M8FeishuConversationChannelProjectionV1,
    M8FeishuDutyRouteV1,
    M8FeishuInboundEventV1,
    M8FeishuInboundJobState,
    M8FeishuInboundJobV1,
    M8FeishuReminderReceiptV1,
    M8FeishuRuntimeHeartbeatV1,
    M8FeishuTurnOrigin,
)
from labcourt.ports.m8_feishu_live import (
    M8FeishuAgentReplyClaim,
    M8FeishuInboundEnqueueResult,
    M8FeishuLiveRepositoryError,
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
        "m8_feishu_duty_route_revisions",
        "m8_feishu_runtime_heartbeats",
        "m8_feishu_live_inbound_events",
        "m8_feishu_live_inbound_artifacts",
        "m8_feishu_inbound_job_events",
        "m8_feishu_agent_conversation_bindings",
        "m8_feishu_agent_turn_origins",
        "m8_feishu_card_action_intents",
        "m8_feishu_card_action_receipts",
        "m8_feishu_alert_bridge_receipts",
        "m8_feishu_reminder_receipts",
        "m8_feishu_agent_reply_outbox",
        "m8_feishu_agent_reply_claim_events",
        "m8_feishu_agent_reply_completions",
    }
)


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("M8 Feishu live timestamp must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _document(value: BaseModel) -> str:
    return canonical_json(value.model_dump(mode="json", exclude_computed_fields=True))


def _sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _load(model: type[BaseModel], document: str) -> BaseModel:
    try:
        return model.model_validate_json(document)
    except ValidationError as error:
        raise RepositoryIntegrityError("M8 Feishu live persisted contract is invalid") from error


class SQLiteM8FeishuLiveRepository:
    """Persist live Feishu state without mutating previously committed authority."""

    def __init__(
        self,
        database_path: str | Path,
        busy_timeout_ms: int,
        repository_manifest_id: Sha256Hex,
        clock: Callable[[], datetime],
    ) -> None:
        self._database_path = Path(database_path)
        self._busy_timeout_ms = _validate_busy_timeout(busy_timeout_ms)
        self._repository_manifest_id = repository_manifest_id
        if len(repository_manifest_id) != 64:
            raise ValueError("M8 Feishu live repository manifest must be SHA-256")
        if not callable(clock):
            raise TypeError("M8 Feishu live repository clock must be callable")
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
    ) -> SQLiteM8FeishuLiveRepository:
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
    def _write(self) -> Iterator[sqlite3.Connection]:
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
                raise M8FeishuLiveRepositoryError("M8 Feishu live writer is busy") from error
            raise
        finally:
            if connection is not None:
                connection.close()

    @staticmethod
    def _require_schema(connection: sqlite3.Connection) -> None:
        migration = connection.execute(
            "SELECT name FROM schema_migrations WHERE version = 15"
        ).fetchone()
        if migration is None or _row_str(migration, "name") != "m8_feishu_live":
            raise RepositoryIntegrityError("M8 Feishu live migration 0015 is not installed")
        observed = {
            _row_str(row, "name")
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE name IN ({})".format(
                    ",".join("?" for _ in _REQUIRED_OBJECTS)
                ),
                tuple(sorted(_REQUIRED_OBJECTS)),
            ).fetchall()
        }
        if observed != _REQUIRED_OBJECTS:
            raise RepositoryIntegrityError("M8 Feishu live persistence layout is incomplete")

    def commit_duty_route(self, route: M8FeishuDutyRouteV1) -> M8FeishuDutyRouteV1:
        if route.repository_manifest_id != self._repository_manifest_id:
            raise M8FeishuLiveRepositoryError("duty route manifest mismatch")
        with self._write() as connection:
            existing = connection.execute(
                "SELECT route_json FROM m8_feishu_duty_route_revisions WHERE route_id = ?",
                (route.route_id,),
            ).fetchone()
            if existing is not None:
                persisted = _load(M8FeishuDutyRouteV1, _row_str(existing, "route_json"))
                if persisted != route:
                    raise M8FeishuLiveRepositoryError("duty route identity collision")
                return route
            current = connection.execute(
                "SELECT route_id, route_revision FROM m8_feishu_duty_route_revisions "
                "ORDER BY route_revision DESC LIMIT 1"
            ).fetchone()
            expected_revision = 1 if current is None else _row_int(current, "route_revision") + 1
            expected_prior = None if current is None else _row_str(current, "route_id")
            if route.route_revision != expected_revision or route.prior_route_id != expected_prior:
                raise M8FeishuLiveRepositoryError("duty route revision fence changed")
            connection.execute(
                "INSERT INTO m8_feishu_duty_route_revisions VALUES (?, ?, ?, ?)",
                (
                    route.route_id,
                    route.route_revision,
                    _document(route),
                    _utc_text(route.committed_at),
                ),
            )
        return route

    def current_duty_route(self) -> M8FeishuDutyRouteV1 | None:
        with self._read() as connection:
            row = connection.execute(
                "SELECT route_json FROM m8_feishu_duty_route_revisions "
                "ORDER BY route_revision DESC LIMIT 1"
            ).fetchone()
        return None if row is None else M8FeishuDutyRouteV1.model_validate_json(
            _row_str(row, "route_json")
        )

    def record_heartbeat(
        self, heartbeat: M8FeishuRuntimeHeartbeatV1
    ) -> M8FeishuRuntimeHeartbeatV1:
        with self._write() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO m8_feishu_runtime_heartbeats VALUES (?, ?, ?, ?)",
                (
                    heartbeat.heartbeat_id,
                    heartbeat.component,
                    _document(heartbeat),
                    _utc_text(heartbeat.observed_at),
                ),
            )
        return heartbeat

    def latest_heartbeat(self, component: str) -> M8FeishuRuntimeHeartbeatV1 | None:
        with self._read() as connection:
            row = connection.execute(
                "SELECT heartbeat_json FROM m8_feishu_runtime_heartbeats "
                "WHERE component = ? ORDER BY observed_at DESC, heartbeat_id DESC LIMIT 1",
                (component,),
            ).fetchone()
        return None if row is None else M8FeishuRuntimeHeartbeatV1.model_validate_json(
            _row_str(row, "heartbeat_json")
        )

    def enqueue_inbound(
        self,
        event: M8FeishuInboundEventV1,
        sanitized_event: bytes,
        message_content: bytes | None,
    ) -> M8FeishuInboundEnqueueResult:
        if _sha_bytes(sanitized_event) != event.raw_event_sha256:
            raise M8FeishuLiveRepositoryError("sanitized inbound event digest mismatch")
        if (message_content is None) != (event.content_ref is None):
            raise M8FeishuLiveRepositoryError("inbound message content authority mismatch")
        if message_content is not None and _sha_bytes(message_content) != event.content_sha256:
            raise M8FeishuLiveRepositoryError("inbound message content digest mismatch")
        with self._write() as connection:
            prior = connection.execute(
                "SELECT event_json FROM m8_feishu_live_inbound_events WHERE provider_event_id = ?",
                (event.provider_event_id,),
            ).fetchone()
            if prior is not None:
                persisted = M8FeishuInboundEventV1.model_validate_json(
                    _row_str(prior, "event_json")
                )
                row = connection.execute(
                    "SELECT job_json FROM m8_feishu_inbound_job_events "
                    "WHERE inbound_event_id = ? ORDER BY state_revision DESC LIMIT 1",
                    (persisted.inbound_event_id,),
                ).fetchone()
                if row is None:
                    raise RepositoryIntegrityError("deduplicated inbound event has no job")
                return M8FeishuInboundEnqueueResult(
                    job=M8FeishuInboundJobV1.model_validate_json(_row_str(row, "job_json")),
                    duplicate=True,
                )
            connection.execute(
                "INSERT INTO m8_feishu_live_inbound_events VALUES (?, ?, ?, ?, ?)",
                (
                    event.inbound_event_id,
                    event.provider_event_id,
                    event.event_kind,
                    _document(event),
                    _utc_text(event.received_at),
                ),
            )
            artifacts = [(event.raw_event_ref, "SANITIZED_EVENT", sanitized_event)]
            if message_content is not None and event.content_ref is not None:
                artifacts.append((event.content_ref, "MESSAGE_CONTENT", message_content))
            for artifact_ref, artifact_kind, content in artifacts:
                connection.execute(
                    "INSERT INTO m8_feishu_live_inbound_artifacts VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        artifact_ref,
                        event.inbound_event_id,
                        artifact_kind,
                        _sha_bytes(content),
                        len(content),
                        content,
                    ),
                )
            job = M8FeishuInboundJobV1(
                inbound_event=event,
                state=M8FeishuInboundJobState.QUEUED,
                state_revision=1,
                occurred_at=self._clock(),
                repository_manifest_id=self._repository_manifest_id,
            )
            self._insert_job(connection, job)
        return M8FeishuInboundEnqueueResult(job=job, duplicate=False)

    def claim_inbound(self, inbound_event_id: str | None = None) -> M8FeishuInboundJobV1 | None:
        with self._write() as connection:
            event_filter = "" if inbound_event_id is None else "AND queued.inbound_event_id = ? "
            parameters: tuple[str, ...] = () if inbound_event_id is None else (inbound_event_id,)
            row = connection.execute(
                "SELECT queued.job_json FROM m8_feishu_inbound_job_events AS queued "
                "WHERE queued.state = 'QUEUED' AND NOT EXISTS ("
                "SELECT 1 FROM m8_feishu_inbound_job_events AS next "
                "WHERE next.inbound_event_id = queued.inbound_event_id "
                "AND next.state_revision > 1) "
                + event_filter
                + "ORDER BY queued.occurred_at, queued.inbound_event_id LIMIT 1",
                parameters,
            ).fetchone()
            if row is None:
                return None
            queued = M8FeishuInboundJobV1.model_validate_json(_row_str(row, "job_json"))
            claimed = queued.model_copy(
                update={
                    "state": M8FeishuInboundJobState.CLAIMED,
                    "state_revision": 2,
                    "occurred_at": self._clock(),
                }
            )
            self._insert_job(connection, claimed)
            return claimed

    def commit_inbound_job(self, job: M8FeishuInboundJobV1) -> M8FeishuInboundJobV1:
        if job.state_revision != 3:
            raise M8FeishuLiveRepositoryError("only terminal inbound jobs may be committed")
        with self._write() as connection:
            prior = connection.execute(
                "SELECT job_json FROM m8_feishu_inbound_job_events "
                "WHERE inbound_event_id = ? AND state_revision = 3",
                (job.inbound_event.inbound_event_id,),
            ).fetchone()
            if prior is not None:
                persisted = M8FeishuInboundJobV1.model_validate_json(
                    _row_str(prior, "job_json")
                )
                if persisted != job:
                    raise M8FeishuLiveRepositoryError("inbound job already completed differently")
                return persisted
            self._insert_job(connection, job)
        return job

    @staticmethod
    def _insert_job(connection: sqlite3.Connection, job: M8FeishuInboundJobV1) -> None:
        connection.execute(
            "INSERT INTO m8_feishu_inbound_job_events VALUES (?, ?, ?, ?, ?, ?)",
            (
                job.job_event_id,
                job.inbound_event.inbound_event_id,
                job.state_revision,
                job.state,
                _document(job),
                _utc_text(job.occurred_at),
            ),
        )

    def read_inbound_content(self, event: M8FeishuInboundEventV1) -> bytes | None:
        if event.content_ref is None:
            return None
        with self._read() as connection:
            row = connection.execute(
                "SELECT content_bytes, content_sha256 FROM m8_feishu_live_inbound_artifacts "
                "WHERE artifact_ref = ? AND artifact_kind = 'MESSAGE_CONTENT'",
                (event.content_ref,),
            ).fetchone()
        if row is None:
            raise RepositoryIntegrityError("M8 Feishu inbound content is absent")
        content = bytes(row["content_bytes"])
        if _sha_bytes(content) != _row_str(row, "content_sha256"):
            raise RepositoryIntegrityError("M8 Feishu inbound content digest changed")
        return content

    def bind_conversation(
        self, projection: M8FeishuConversationChannelProjectionV1
    ) -> M8FeishuConversationChannelProjectionV1:
        if projection.turn_origins:
            raise M8FeishuLiveRepositoryError("new channel binding cannot predeclare turn origins")
        with self._write() as connection:
            existing = connection.execute(
                "SELECT projection_json FROM m8_feishu_agent_conversation_bindings "
                "WHERE actor_id = ? OR conversation_id = ?",
                (projection.actor_id, projection.conversation_id),
            ).fetchone()
            if existing is not None:
                persisted = M8FeishuConversationChannelProjectionV1.model_validate_json(
                    _row_str(existing, "projection_json")
                )
                if persisted != projection:
                    raise M8FeishuLiveRepositoryError(
                        "actor already has another Feishu conversation"
                    )
                return persisted
            connection.execute(
                "INSERT INTO m8_feishu_agent_conversation_bindings VALUES (?, ?, ?, ?, ?)",
                (
                    projection.conversation_id,
                    projection.actor_id,
                    projection.binding_revision,
                    _document(projection),
                    _utc_text(projection.bound_at),
                ),
            )
        return projection

    def channel_projection(
        self, conversation_id: str
    ) -> M8FeishuConversationChannelProjectionV1 | None:
        return self._projection("conversation_id", conversation_id)

    def actor_channel_projection(
        self, actor_id: str
    ) -> M8FeishuConversationChannelProjectionV1 | None:
        return self._projection("actor_id", actor_id)

    def _projection(
        self, field_name: str, value: str
    ) -> M8FeishuConversationChannelProjectionV1 | None:
        if field_name not in {"actor_id", "conversation_id"}:
            raise ValueError("invalid channel projection selector")
        with self._read() as connection:
            row = connection.execute(
                "SELECT projection_json, conversation_id FROM "
                f"m8_feishu_agent_conversation_bindings WHERE {field_name} = ?",
                (value,),
            ).fetchone()
            if row is None:
                return None
            projection = M8FeishuConversationChannelProjectionV1.model_validate_json(
                _row_str(row, "projection_json")
            )
            origins = {
                _row_str(origin, "turn_id"): M8FeishuTurnOrigin(_row_str(origin, "origin"))
                for origin in connection.execute(
                    "SELECT turn_id, origin FROM m8_feishu_agent_turn_origins "
                    "WHERE conversation_id = ? ORDER BY recorded_at, turn_id",
                    (projection.conversation_id,),
                ).fetchall()
            }
        return projection.model_copy(update={"turn_origins": origins})

    def record_turn_origin(
        self, conversation_id: str, turn_id: str, origin: M8FeishuTurnOrigin
    ) -> None:
        with self._write() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO m8_feishu_agent_turn_origins VALUES (?, ?, ?, ?)",
                (turn_id, conversation_id, origin, _utc_text(self._clock())),
            )

    def commit_card_intent(
        self, intent: M8FeishuCardActionIntentV1
    ) -> M8FeishuCardActionIntentV1:
        with self._write() as connection:
            prior = connection.execute(
                "SELECT intent_json FROM m8_feishu_card_action_intents "
                "WHERE confirmation_token_sha256 = ?",
                (intent.confirmation_token_sha256,),
            ).fetchone()
            if prior is not None:
                persisted = M8FeishuCardActionIntentV1.model_validate_json(
                    _row_str(prior, "intent_json")
                )
                if persisted != intent:
                    raise M8FeishuLiveRepositoryError(
                        "card token is already bound to another intent"
                    )
                return persisted
            connection.execute(
                "INSERT INTO m8_feishu_card_action_intents VALUES (?, ?, ?, ?, ?)",
                (
                    intent.intent_id,
                    intent.confirmation_token_sha256,
                    _document(intent),
                    _utc_text(intent.expires_at),
                    _utc_text(intent.created_at),
                ),
            )
        return intent

    def card_intent_for_token(self, token_sha256: str) -> M8FeishuCardActionIntentV1 | None:
        with self._read() as connection:
            row = connection.execute(
                "SELECT intent_json FROM m8_feishu_card_action_intents "
                "WHERE confirmation_token_sha256 = ?",
                (token_sha256,),
            ).fetchone()
        return None if row is None else M8FeishuCardActionIntentV1.model_validate_json(
            _row_str(row, "intent_json")
        )

    def commit_card_receipt(
        self, receipt: M8FeishuCardActionReceiptV1
    ) -> M8FeishuCardActionReceiptV1:
        with self._write() as connection:
            prior = connection.execute(
                "SELECT receipt_json FROM m8_feishu_card_action_receipts WHERE intent_id = ?",
                (receipt.intent.intent_id,),
            ).fetchone()
            if prior is not None:
                return M8FeishuCardActionReceiptV1.model_validate_json(
                    _row_str(prior, "receipt_json")
                )
            connection.execute(
                "INSERT INTO m8_feishu_card_action_receipts VALUES (?, ?, ?, ?)",
                (
                    receipt.action_receipt_id,
                    receipt.intent.intent_id,
                    _document(receipt),
                    _utc_text(receipt.completed_at),
                ),
            )
        return receipt

    def card_receipt(self, intent_id: str) -> M8FeishuCardActionReceiptV1 | None:
        with self._read() as connection:
            row = connection.execute(
                "SELECT receipt_json FROM m8_feishu_card_action_receipts WHERE intent_id = ?",
                (intent_id,),
            ).fetchone()
        return None if row is None else M8FeishuCardActionReceiptV1.model_validate_json(
            _row_str(row, "receipt_json")
        )

    def commit_alert_bridge(
        self, receipt: M8FeishuAlertBridgeReceiptV1
    ) -> M8FeishuAlertBridgeReceiptV1:
        with self._write() as connection:
            prior = connection.execute(
                "SELECT receipt_json FROM m8_feishu_alert_bridge_receipts "
                "WHERE source_case_id = ? AND source_case_version = ?",
                (receipt.source_case_id, receipt.source_case_version),
            ).fetchone()
            if prior is not None:
                return M8FeishuAlertBridgeReceiptV1.model_validate_json(
                    _row_str(prior, "receipt_json")
                )
            connection.execute(
                "INSERT INTO m8_feishu_alert_bridge_receipts VALUES (?, ?, ?, ?, ?)",
                (
                    receipt.bridge_receipt_id,
                    receipt.source_case_id,
                    receipt.source_case_version,
                    _document(receipt),
                    _utc_text(receipt.assessed_at),
                ),
            )
        return receipt

    def alert_bridge(
        self, case_id: str, case_version: int
    ) -> M8FeishuAlertBridgeReceiptV1 | None:
        with self._read() as connection:
            row = connection.execute(
                "SELECT receipt_json FROM m8_feishu_alert_bridge_receipts "
                "WHERE source_case_id = ? AND source_case_version = ?",
                (case_id, case_version),
            ).fetchone()
        return None if row is None else M8FeishuAlertBridgeReceiptV1.model_validate_json(
            _row_str(row, "receipt_json")
        )

    def commit_reminder(
        self, receipt: M8FeishuReminderReceiptV1
    ) -> M8FeishuReminderReceiptV1:
        with self._write() as connection:
            prior = connection.execute(
                "SELECT receipt_json FROM m8_feishu_reminder_receipts "
                "WHERE source_dispatch_request_id = ?",
                (receipt.source_dispatch_request_id,),
            ).fetchone()
            if prior is not None:
                return M8FeishuReminderReceiptV1.model_validate_json(
                    _row_str(prior, "receipt_json")
                )
            connection.execute(
                "INSERT INTO m8_feishu_reminder_receipts VALUES (?, ?, ?, ?)",
                (
                    receipt.reminder_receipt_id,
                    receipt.source_dispatch_request_id,
                    _document(receipt),
                    _utc_text(receipt.assessed_at),
                ),
            )
        return receipt

    def reminder(self, dispatch_request_id: str) -> M8FeishuReminderReceiptV1 | None:
        with self._read() as connection:
            row = connection.execute(
                "SELECT receipt_json FROM m8_feishu_reminder_receipts "
                "WHERE source_dispatch_request_id = ?",
                (dispatch_request_id,),
            ).fetchone()
        return None if row is None else M8FeishuReminderReceiptV1.model_validate_json(
            _row_str(row, "receipt_json")
        )

    def enqueue_agent_reply(
        self, envelope: M8FeishuAgentReplyEnvelopeV1, content: bytes
    ) -> M8FeishuAgentReplyEnvelopeV1:
        if (
            len(content) != envelope.content_size_bytes
            or _sha_bytes(content) != envelope.content_sha256
        ):
            raise M8FeishuLiveRepositoryError("Agent reply content authority mismatch")
        with self._write() as connection:
            prior = connection.execute(
                "SELECT envelope_json FROM m8_feishu_agent_reply_outbox WHERE outbox_id = ?",
                (envelope.outbox_id,),
            ).fetchone()
            if prior is not None:
                persisted = M8FeishuAgentReplyEnvelopeV1.model_validate_json(
                    _row_str(prior, "envelope_json")
                )
                if persisted != envelope:
                    raise M8FeishuLiveRepositoryError("Agent reply outbox identity collision")
                return persisted
            connection.execute(
                "INSERT INTO m8_feishu_agent_reply_outbox VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    envelope.outbox_id,
                    _document(envelope),
                    envelope.content_ref,
                    envelope.content_sha256,
                    envelope.content_size_bytes,
                    content,
                    _utc_text(envelope.queued_at),
                ),
            )
        return envelope

    def claim_agent_reply(self, worker_token_sha256: str) -> M8FeishuAgentReplyClaim | None:
        with self._write() as connection:
            row = connection.execute(
                "SELECT outbox_id, envelope_json, content_bytes "
                "FROM m8_feishu_agent_reply_outbox AS o "
                "WHERE NOT EXISTS (SELECT 1 FROM m8_feishu_agent_reply_claim_events AS c "
                "WHERE c.outbox_id = o.outbox_id AND c.claim_kind = 'CLAIMED') "
                "AND NOT EXISTS (SELECT 1 FROM m8_feishu_agent_reply_completions AS d "
                "WHERE d.outbox_id = o.outbox_id) ORDER BY queued_at, outbox_id LIMIT 1"
            ).fetchone()
            if row is None:
                return None
            outbox_id = _row_str(row, "outbox_id")
            claim_fence = 1
            connection.execute(
                "INSERT INTO m8_feishu_agent_reply_claim_events VALUES (?, ?, 'CLAIMED', ?, ?, ?)",
                (
                    sha256_hex(["m8-feishu-agent-reply-claim", outbox_id, worker_token_sha256]),
                    outbox_id,
                    worker_token_sha256,
                    claim_fence,
                    _utc_text(self._clock()),
                ),
            )
            return M8FeishuAgentReplyClaim(
                envelope=M8FeishuAgentReplyEnvelopeV1.model_validate_json(
                    _row_str(row, "envelope_json")
                ),
                content=bytes(row["content_bytes"]),
                worker_token_sha256=worker_token_sha256,
                claim_fence=claim_fence,
            )

    def complete_agent_reply(
        self,
        claim: M8FeishuAgentReplyClaim,
        completion: M8FeishuAgentReplyCompletionV1,
        raw_response: bytes,
    ) -> M8FeishuAgentReplyCompletionV1:
        if completion.envelope != claim.envelope:
            raise M8FeishuLiveRepositoryError("Agent reply completion changed envelope")
        if _sha_bytes(raw_response) != completion.raw_response_sha256:
            raise M8FeishuLiveRepositoryError("Agent reply raw response digest mismatch")
        with self._write() as connection:
            connection.execute(
                "INSERT INTO m8_feishu_agent_reply_completions VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    completion.completion_id,
                    claim.envelope.outbox_id,
                    _document(completion),
                    completion.raw_response_ref,
                    completion.raw_response_sha256,
                    raw_response,
                    _utc_text(completion.completed_at),
                ),
            )
        return completion


__all__ = ["SQLiteM8FeishuLiveRepository"]
