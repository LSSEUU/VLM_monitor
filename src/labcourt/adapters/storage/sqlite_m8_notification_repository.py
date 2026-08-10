"""SQLite-backed M8 notification targets, outbox lifecycle, audit, and raw bytes."""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from pydantic import ValidationError

from labcourt.application.m8_notification_workflow import (
    build_notification_plan_commit,
    build_notification_target_commit,
    build_notification_transition_commit,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_case_persistence import (
    M8ActorAuthorityCommitReceiptV1,
    M8OperationalCaseCommitReceiptV1,
)
from labcourt.contracts.m8_notification_lifecycle import (
    M8NotificationInitiatorKind,
    M8NotificationTransitionCommandV1,
)
from labcourt.contracts.m8_notification_persistence import (
    MAX_M8_NOTIFICATION_RAW_ARTIFACT_BYTES,
    M8NotificationAuditEventV1,
    M8NotificationCommitReceiptV1,
    M8NotificationRawArtifactCommitReceiptV1,
    M8NotificationTargetCommitReceiptV1,
)
from labcourt.contracts.m8_notifications import (
    M8NotificationChannelKind,
    M8NotificationPlanAuthorityV1,
    M8NotificationStatus,
    M8NotificationTargetAuthorityV1,
)
from labcourt.contracts.references import require_reference_token
from labcourt.exceptions import BudgetExceeded, ConcurrentModification, EvidenceMissing

from .sqlite_m8_operations_repository import M8_MIGRATIONS
from .sqlite_repository import (
    MigrationRunner,
    RepositoryIntegrityError,
    _is_sqlite_concurrency_error,
    _open_connection,
    _row_int,
    _row_optional_str,
    _row_str,
    _validate_busy_timeout,
)

_M8_NOTIFICATION_REQUIRED_OBJECTS = frozenset(
    {
        "m8_notification_targets",
        "idx_m8_notification_targets_current",
        "m8_notification_raw_artifacts",
        "m8_notification_versions",
        "idx_m8_notifications_current",
        "idx_m8_notifications_status_current",
        "m8_notification_version_raw_artifacts",
        "m8_notification_targets_validate_contiguous",
        "m8_notification_versions_validate_contiguous",
        "m8_notification_targets_no_update",
        "m8_notification_targets_no_delete",
        "m8_notification_targets_no_replace",
        "m8_notification_raw_artifacts_no_update",
        "m8_notification_raw_artifacts_no_delete",
        "m8_notification_raw_artifacts_no_replace",
        "m8_notification_versions_no_update",
        "m8_notification_versions_no_delete",
        "m8_notification_versions_no_replace",
        "m8_notification_version_raw_artifacts_no_update",
        "m8_notification_version_raw_artifacts_no_delete",
        "m8_notification_version_raw_artifacts_no_replace",
    }
)


def _validate_sha256(value: str, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"M8 {name} must be lowercase SHA-256 hex")
    return value


class SQLiteM8NotificationRepository:
    """Append-only notification repository using the isolated M8 database."""

    def __init__(
        self,
        database_path: str | Path,
        busy_timeout_ms: int,
        repository_manifest_id: Sha256Hex,
    ) -> None:
        self._database_path = Path(database_path)
        self._busy_timeout_ms = _validate_busy_timeout(busy_timeout_ms)
        self._repository_manifest_id = _validate_sha256(
            repository_manifest_id,
            "repository_manifest_id",
        )
        with self._read() as connection:
            self._require_schema(connection)

    @classmethod
    def initialize(
        cls,
        database_path: str | Path,
        busy_timeout_ms: int,
        repository_manifest_id: Sha256Hex,
    ) -> SQLiteM8NotificationRepository:
        MigrationRunner(
            database_path,
            busy_timeout_ms,
            migrations_path=M8_MIGRATIONS,
        ).apply_all()
        return cls(database_path, busy_timeout_ms, repository_manifest_id)

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
            if isinstance(error, sqlite3.OperationalError) and _is_sqlite_concurrency_error(error):
                raise ConcurrentModification(
                    "M8 notification SQLite writer lock could not be acquired"
                ) from error
            raise
        finally:
            if connection is not None:
                connection.close()

    @staticmethod
    def _require_schema(connection: sqlite3.Connection) -> None:
        try:
            migrations = connection.execute(
                """
                SELECT version, name FROM schema_migrations
                WHERE version IN (1, 2, 3, 4) ORDER BY version
                """
            ).fetchall()
        except sqlite3.DatabaseError as error:
            raise RepositoryIntegrityError("M8 notification migration ledger is invalid") from error
        observed_migrations = tuple(
            (_row_int(row, "version"), _row_str(row, "name")) for row in migrations
        )
        if observed_migrations != (
            (1, "m8_actor_case_authority"),
            (2, "m8_campus_inventory"),
            (3, "m8_sensor_cache"),
            (4, "m8_notification_outbox"),
        ):
            raise RepositoryIntegrityError("M8 notification migrations 0001-0004 are not installed")
        observed = {
            _row_str(row, "name")
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE name IN ({})".format(
                    ",".join("?" for _name in _M8_NOTIFICATION_REQUIRED_OBJECTS)
                ),
                tuple(sorted(_M8_NOTIFICATION_REQUIRED_OBJECTS)),
            ).fetchall()
        }
        if observed != _M8_NOTIFICATION_REQUIRED_OBJECTS:
            raise RepositoryIntegrityError("M8 notification persistence layout is incomplete")

    def publish_target_authority(
        self,
        target: M8NotificationTargetAuthorityV1,
        expected_prior_revision: int | None,
    ) -> M8NotificationTargetCommitReceiptV1:
        if not isinstance(target, M8NotificationTargetAuthorityV1):
            raise TypeError("M8 target publication requires M8NotificationTargetAuthorityV1")
        if expected_prior_revision is not None and (
            not isinstance(expected_prior_revision, int)
            or isinstance(expected_prior_revision, bool)
            or expected_prior_revision < 1
        ):
            raise ValueError("M8 target expected prior revision must be a positive integer")
        with self._immediate() as connection:
            actor = self._load_current_actor(connection, target.actor_id)
            if not actor.authority.active:
                raise ConcurrentModification("M8 notification target actor is inactive")
            existing_row = connection.execute(
                """
                SELECT * FROM m8_notification_targets
                WHERE actor_id = ? AND channel = ? AND authority_revision = ?
                """,
                (target.actor_id, target.channel.value, target.authority_revision),
            ).fetchone()
            if existing_row is not None:
                existing = self._load_target_row(existing_row)
                expected_existing = target.authority_revision - 1 or None
                if existing.target == target and expected_prior_revision == expected_existing:
                    return existing
                raise ConcurrentModification("M8 notification target revision already exists")
            prior_row = connection.execute(
                """
                SELECT * FROM m8_notification_targets
                WHERE actor_id = ? AND channel = ?
                ORDER BY authority_revision DESC LIMIT 1
                """,
                (target.actor_id, target.channel.value),
            ).fetchone()
            prior = self._load_target_row(prior_row) if prior_row is not None else None
            actual_prior_revision = prior.target.authority_revision if prior is not None else None
            if actual_prior_revision != expected_prior_revision:
                raise ConcurrentModification("M8 notification target prior revision is stale")
            try:
                candidate = build_notification_target_commit(
                    target,
                    prior,
                    self._repository_manifest_id,
                )
            except ValueError as error:
                raise ConcurrentModification(str(error)) from error
            self._insert_target(connection, candidate)
            return candidate

    def get_current_target_authority(
        self,
        actor_id: str,
        channel: M8NotificationChannelKind,
    ) -> M8NotificationTargetCommitReceiptV1:
        require_reference_token(actor_id, "M8 notification target actor")
        if not isinstance(channel, M8NotificationChannelKind):
            raise TypeError("M8 notification channel must be M8NotificationChannelKind")
        with self._read() as connection:
            row = connection.execute(
                """
                SELECT * FROM m8_notification_targets
                WHERE actor_id = ? AND channel = ?
                ORDER BY authority_revision DESC LIMIT 1
                """,
                (actor_id, channel.value),
            ).fetchone()
            if row is None:
                raise EvidenceMissing("M8 notification target was not found")
            return self._load_target_row(row)

    def create_notification(
        self,
        plan: M8NotificationPlanAuthorityV1,
        audit_manifest_id: str,
    ) -> M8NotificationCommitReceiptV1:
        if not isinstance(plan, M8NotificationPlanAuthorityV1):
            raise TypeError("M8 notification creation requires M8NotificationPlanAuthorityV1")
        audit_manifest = _validate_sha256(audit_manifest_id, "notification audit manifest")
        with self._immediate() as connection:
            existing_row = connection.execute(
                """
                SELECT * FROM m8_notification_versions
                WHERE notification_id = ? AND notification_version = 1
                """,
                (plan.notification_id,),
            ).fetchone()
            if existing_row is not None:
                existing = self._load_notification_row(connection, existing_row)
                if (
                    existing.audit_event.notification_authority.plan == plan
                    and existing.audit_event.audit_manifest_id == audit_manifest
                ):
                    return existing
                raise ConcurrentModification("M8 notification plan identity already exists")
            case = self._load_current_case(connection, plan.case_id)
            target = self._load_current_target(
                connection,
                plan.target.actor_id,
                plan.target.channel,
            )
            actor = self._load_current_actor(connection, plan.target.actor_id)
            try:
                candidate = build_notification_plan_commit(
                    plan,
                    case,
                    target,
                    actor,
                    audit_manifest,
                    self._repository_manifest_id,
                )
            except ValueError as error:
                raise ConcurrentModification(str(error)) from error
            self._insert_notification(connection, candidate)
            return candidate

    def get_current_notification(
        self,
        notification_id: str,
    ) -> M8NotificationCommitReceiptV1:
        require_reference_token(notification_id, "M8 notification_id")
        with self._read() as connection:
            row = connection.execute(
                """
                SELECT * FROM m8_notification_versions
                WHERE notification_id = ? ORDER BY notification_version DESC LIMIT 1
                """,
                (notification_id,),
            ).fetchone()
            if row is None:
                raise EvidenceMissing("M8 notification was not found")
            return self._load_notification_row(connection, row)

    def transition_notification(
        self,
        command: M8NotificationTransitionCommandV1,
        raw_artifacts: tuple[bytes, ...],
        raw_storage_manifest_id: str,
        audit_manifest_id: str,
    ) -> M8NotificationCommitReceiptV1:
        if not isinstance(command, M8NotificationTransitionCommandV1):
            raise TypeError("M8 notification transition requires a typed command")
        if not isinstance(raw_artifacts, tuple) or any(
            not isinstance(item, bytes) for item in raw_artifacts
        ):
            raise TypeError("M8 notification raw artifacts must be a tuple of exact bytes")
        raw_manifest = _validate_sha256(
            raw_storage_manifest_id,
            "notification raw storage manifest",
        )
        audit_manifest = _validate_sha256(audit_manifest_id, "notification audit manifest")
        with self._immediate() as connection:
            existing_row = connection.execute(
                """
                SELECT * FROM m8_notification_versions WHERE transition_command_id = ?
                """,
                (command.command_id,),
            ).fetchone()
            if existing_row is not None:
                existing = self._load_notification_row(connection, existing_row)
                if (
                    existing.audit_event.transition_command == command
                    and existing.audit_event.audit_manifest_id == audit_manifest
                ):
                    self._verify_retry_raw(existing, raw_artifacts, raw_manifest)
                    return existing
                raise ConcurrentModification(
                    "M8 notification command already committed with different authority"
                )
            before_row = connection.execute(
                """
                SELECT * FROM m8_notification_versions
                WHERE notification_id = ? ORDER BY notification_version DESC LIMIT 1
                """,
                (command.notification_id,),
            ).fetchone()
            if before_row is None:
                raise EvidenceMissing("M8 notification was not found")
            before = self._load_notification_row(connection, before_row)
            resolved_actor = None
            if command.initiator_kind == M8NotificationInitiatorKind.ACTOR:
                if command.actor_authority is None:
                    raise ConcurrentModification("M8 notification actor command is incomplete")
                resolved_actor = self._load_current_actor(
                    connection,
                    command.actor_authority.actor_id,
                )
            try:
                candidate = build_notification_transition_commit(
                    before,
                    command,
                    raw_artifacts,
                    raw_manifest,
                    resolved_actor,
                    audit_manifest,
                    self._repository_manifest_id,
                )
            except ValueError as error:
                raise ConcurrentModification(str(error)) from error
            for receipt, raw_bytes in zip(
                candidate.raw_artifact_receipts,
                raw_artifacts,
                strict=True,
            ):
                self._insert_or_verify_raw(connection, receipt, raw_bytes)
            self._insert_notification(connection, candidate)
            return candidate

    def list_notifications_by_status(
        self,
        status: M8NotificationStatus,
        limit: int,
    ) -> tuple[M8NotificationCommitReceiptV1, ...]:
        if not isinstance(status, M8NotificationStatus):
            raise TypeError("M8 notification status must be M8NotificationStatus")
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 1000:
            raise ValueError("M8 notification list limit must be from 1 through 1000")
        with self._read() as connection:
            rows = connection.execute(
                """
                SELECT current.* FROM m8_notification_versions AS current
                WHERE current.status = ?
                  AND NOT EXISTS (
                    SELECT 1 FROM m8_notification_versions AS newer
                    WHERE newer.notification_id = current.notification_id
                      AND newer.notification_version > current.notification_version
                  )
                ORDER BY current.notification_id LIMIT ?
                """,
                (status.value, limit),
            ).fetchall()
            return tuple(self._load_notification_row(connection, row) for row in rows)

    def list_current_notifications(
        self,
        limit: int,
    ) -> tuple[M8NotificationCommitReceiptV1, ...]:
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 20_000:
            raise ValueError("M8 current notification limit must be from 1 through 20000")
        with self._read() as connection:
            rows = connection.execute(
                """
                SELECT current.* FROM m8_notification_versions AS current
                WHERE NOT EXISTS (
                    SELECT 1 FROM m8_notification_versions AS newer
                    WHERE newer.notification_id = current.notification_id
                      AND newer.notification_version > current.notification_version
                )
                ORDER BY current.notification_id LIMIT ?
                """,
                (limit + 1,),
            ).fetchall()
            if len(rows) > limit:
                raise BudgetExceeded("M8 current notification inventory exceeds the limit")
            return tuple(self._load_notification_row(connection, row) for row in rows)

    def list_notification_audit(
        self,
        notification_id: str,
    ) -> tuple[M8NotificationAuditEventV1, ...]:
        require_reference_token(notification_id, "M8 notification_id")
        with self._read() as connection:
            rows = connection.execute(
                """
                SELECT * FROM m8_notification_versions
                WHERE notification_id = ? ORDER BY notification_version
                """,
                (notification_id,),
            ).fetchall()
            if not rows:
                raise EvidenceMissing("M8 notification audit was not found")
            receipts = tuple(self._load_notification_row(connection, row) for row in rows)
            for index, receipt in enumerate(receipts):
                if receipt.notification_version != index + 1:
                    raise RepositoryIntegrityError("M8 notification versions are not contiguous")
                if index and receipt.audit_event.prior_audit_event_sha256 != (
                    receipts[index - 1].audit_event_sha256
                ):
                    raise RepositoryIntegrityError("M8 notification audit chain is broken")
            return tuple(receipt.audit_event for receipt in receipts)

    def read_raw_artifact(self, raw_artifact_ref: str) -> bytes:
        require_reference_token(raw_artifact_ref, "M8 notification raw artifact")
        with self._read() as connection:
            row = connection.execute(
                "SELECT * FROM m8_notification_raw_artifacts WHERE raw_artifact_ref = ?",
                (raw_artifact_ref,),
            ).fetchone()
            if row is None:
                raise EvidenceMissing("M8 notification raw artifact was not found")
            return self._validated_raw_bytes(row)

    def _load_current_target(
        self,
        connection: sqlite3.Connection,
        actor_id: str,
        channel: M8NotificationChannelKind,
    ) -> M8NotificationTargetCommitReceiptV1:
        row = connection.execute(
            """
            SELECT * FROM m8_notification_targets
            WHERE actor_id = ? AND channel = ?
            ORDER BY authority_revision DESC LIMIT 1
            """,
            (actor_id, channel.value),
        ).fetchone()
        if row is None:
            raise EvidenceMissing("M8 notification target was not found")
        return self._load_target_row(row)

    def _load_current_actor(
        self,
        connection: sqlite3.Connection,
        actor_id: str,
    ) -> M8ActorAuthorityCommitReceiptV1:
        row = connection.execute(
            """
            SELECT * FROM m8_actor_authorities
            WHERE actor_id = ? ORDER BY authority_revision DESC LIMIT 1
            """,
            (actor_id,),
        ).fetchone()
        if row is None:
            raise EvidenceMissing("M8 notification actor authority was not found")
        raw = _row_str(row, "receipt_json")
        try:
            receipt = M8ActorAuthorityCommitReceiptV1.model_validate_json(raw)
        except ValidationError as error:
            raise RepositoryIntegrityError("persisted M8 notification actor is invalid") from error
        if (
            canonical_json(receipt.model_dump(mode="json")) != raw
            or receipt.authority.actor_id != _row_str(row, "actor_id")
            or receipt.authority.authority_revision != _row_int(row, "authority_revision")
            or receipt.authority.actor_authority_id != _row_str(row, "actor_authority_id")
            or receipt.authority_document_sha256 != _row_str(row, "authority_document_sha256")
            or receipt.repository_manifest_id != self._repository_manifest_id
        ):
            raise RepositoryIntegrityError("M8 notification actor index conflicts with receipt")
        return receipt

    def _load_current_case(
        self,
        connection: sqlite3.Connection,
        case_id: str,
    ) -> M8OperationalCaseCommitReceiptV1:
        row = connection.execute(
            """
            SELECT * FROM m8_operational_case_versions
            WHERE case_id = ? ORDER BY case_version DESC LIMIT 1
            """,
            (case_id,),
        ).fetchone()
        if row is None:
            raise EvidenceMissing("M8 notification Case was not found")
        raw = _row_str(row, "commit_receipt_json")
        try:
            receipt = M8OperationalCaseCommitReceiptV1.model_validate_json(raw)
        except ValidationError as error:
            raise RepositoryIntegrityError("persisted M8 notification Case is invalid") from error
        if (
            canonical_json(receipt.model_dump(mode="json")) != raw
            or receipt.case_id != _row_str(row, "case_id")
            or receipt.case_version != _row_int(row, "case_version")
            or receipt.status.value != _row_str(row, "status")
            or receipt.case_document_sha256 != _row_str(row, "case_document_sha256")
            or receipt.repository_manifest_id != self._repository_manifest_id
        ):
            raise RepositoryIntegrityError("M8 notification Case index conflicts with receipt")
        return receipt

    def _load_target_row(self, row: sqlite3.Row) -> M8NotificationTargetCommitReceiptV1:
        raw = _row_str(row, "receipt_json")
        try:
            receipt = M8NotificationTargetCommitReceiptV1.model_validate_json(raw)
        except ValidationError as error:
            raise RepositoryIntegrityError("persisted M8 notification target is invalid") from error
        target = receipt.target
        if (
            canonical_json(receipt.model_dump(mode="json")) != raw
            or target.actor_id != _row_str(row, "actor_id")
            or target.channel.value != _row_str(row, "channel")
            or target.authority_revision != _row_int(row, "authority_revision")
            or target.target_authority_id != _row_str(row, "target_authority_id")
            or receipt.target_document_sha256 != _row_str(row, "target_document_sha256")
            or int(target.active) != _row_int(row, "active")
            or receipt.prior_target_authority_id
            != _row_optional_str(row, "prior_target_authority_id")
            or receipt.prior_document_sha256 != _row_optional_str(row, "prior_document_sha256")
            or receipt.repository_manifest_id != self._repository_manifest_id
            or receipt.commit_receipt_id != _row_str(row, "commit_receipt_id")
        ):
            raise RepositoryIntegrityError("M8 notification target index conflicts with receipt")
        return receipt

    def _load_notification_row(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> M8NotificationCommitReceiptV1:
        raw = _row_str(row, "commit_receipt_json")
        try:
            receipt = M8NotificationCommitReceiptV1.model_validate_json(raw)
        except ValidationError as error:
            raise RepositoryIntegrityError(
                "persisted M8 notification receipt is invalid"
            ) from error
        event = receipt.audit_event
        authority = event.notification_authority
        plan = authority.plan
        if (
            canonical_json(receipt.model_dump(mode="json")) != raw
            or canonical_json(authority.model_dump(mode="json"))
            != _row_str(row, "notification_json")
            or canonical_json(event.model_dump(mode="json")) != _row_str(row, "audit_event_json")
            or receipt.notification_id != _row_str(row, "notification_id")
            or receipt.notification_version != _row_int(row, "notification_version")
            or receipt.status.value != _row_str(row, "status")
            or plan.case_id != _row_str(row, "case_id")
            or plan.case_version != _row_int(row, "case_version")
            or plan.target.actor_id != _row_str(row, "target_actor_id")
            or plan.target.channel.value != _row_str(row, "target_channel")
            or plan.target.authority_revision != _row_int(row, "target_authority_revision")
            or plan.target.target_authority_id != _row_str(row, "target_authority_id")
            or plan.notification_id != _row_str(row, "plan_authority_id")
            or receipt.notification_authority_id != _row_str(row, "notification_authority_id")
            or receipt.notification_document_sha256 != _row_str(row, "notification_document_sha256")
            or authority.prior_notification_document_sha256
            != _row_optional_str(row, "prior_notification_document_sha256")
            or authority.last_transition_command_id
            != _row_optional_str(row, "transition_command_id")
            or authority.last_initiator_authority_id
            != _row_optional_str(row, "initiator_authority_id")
            or event.resolved_actor_document_sha256
            != _row_optional_str(row, "resolved_actor_document_sha256")
            or authority.last_dispatch_result_id != _row_optional_str(row, "dispatch_result_id")
            or authority.last_delivery_receipt_id != _row_optional_str(row, "delivery_receipt_id")
            or authority.last_reply_authority_id != _row_optional_str(row, "reply_authority_id")
            or len(receipt.raw_artifact_receipts) != _row_int(row, "raw_artifact_count")
            or receipt.raw_artifact_inventory_sha256
            != _row_str(row, "raw_artifact_inventory_sha256")
            or receipt.total_raw_artifact_size_bytes
            != _row_int(row, "total_raw_artifact_size_bytes")
            or receipt.audit_event_id != _row_str(row, "audit_event_id")
            or receipt.audit_event_sha256 != _row_str(row, "audit_event_sha256")
            or event.prior_audit_event_sha256 != _row_str(row, "prior_audit_event_sha256")
            or receipt.repository_manifest_id != self._repository_manifest_id
            or receipt.commit_receipt_id != _row_str(row, "commit_receipt_id")
        ):
            raise RepositoryIntegrityError("M8 notification index columns conflict with receipt")
        target_row = connection.execute(
            "SELECT * FROM m8_notification_targets WHERE target_authority_id = ?",
            (plan.target.target_authority_id,),
        ).fetchone()
        if target_row is None or self._load_target_row(target_row).target != plan.target:
            raise RepositoryIntegrityError("M8 notification target authority is missing")
        links = connection.execute(
            """
            SELECT position, raw_artifact_ref FROM m8_notification_version_raw_artifacts
            WHERE notification_id = ? AND notification_version = ? ORDER BY position
            """,
            (receipt.notification_id, receipt.notification_version),
        ).fetchall()
        expected_links = tuple(
            (position, item.raw_artifact_ref)
            for position, item in enumerate(receipt.raw_artifact_receipts)
        )
        observed_links = tuple(
            (_row_int(link, "position"), _row_str(link, "raw_artifact_ref")) for link in links
        )
        if observed_links != expected_links:
            raise RepositoryIntegrityError("M8 notification raw artifact links are incomplete")
        for raw_receipt in receipt.raw_artifact_receipts:
            raw_row = connection.execute(
                "SELECT * FROM m8_notification_raw_artifacts WHERE raw_artifact_ref = ?",
                (raw_receipt.raw_artifact_ref,),
            ).fetchone()
            if raw_row is None:
                raise RepositoryIntegrityError("M8 notification raw artifact is missing")
            self._validate_raw_row(raw_row, raw_receipt)
        return receipt

    def _insert_target(
        self,
        connection: sqlite3.Connection,
        receipt: M8NotificationTargetCommitReceiptV1,
    ) -> None:
        target = receipt.target
        try:
            connection.execute(
                """
                INSERT INTO m8_notification_targets(
                    actor_id, channel, authority_revision, target_authority_id,
                    target_document_sha256, active, prior_target_authority_id,
                    prior_document_sha256, repository_manifest_id,
                    commit_receipt_id, receipt_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    target.actor_id,
                    target.channel.value,
                    target.authority_revision,
                    target.target_authority_id,
                    receipt.target_document_sha256,
                    int(target.active),
                    receipt.prior_target_authority_id,
                    receipt.prior_document_sha256,
                    receipt.repository_manifest_id,
                    receipt.commit_receipt_id,
                    canonical_json(receipt.model_dump(mode="json")),
                ),
            )
        except sqlite3.IntegrityError as error:
            raise ConcurrentModification("M8 notification target append was rejected") from error

    def _insert_or_verify_raw(
        self,
        connection: sqlite3.Connection,
        receipt: M8NotificationRawArtifactCommitReceiptV1,
        raw_bytes: bytes,
    ) -> None:
        row = connection.execute(
            "SELECT * FROM m8_notification_raw_artifacts WHERE raw_artifact_ref = ?",
            (receipt.raw_artifact_ref,),
        ).fetchone()
        if row is not None:
            if self._validate_raw_row(row, receipt) != raw_bytes:
                raise ConcurrentModification("M8 notification raw reference has different bytes")
            return
        try:
            connection.execute(
                """
                INSERT INTO m8_notification_raw_artifacts(
                    raw_artifact_ref, raw_artifact_sha256, raw_artifact_size_bytes,
                    raw_artifact_bytes, raw_storage_manifest_id,
                    repository_manifest_id, raw_commit_receipt_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    receipt.raw_artifact_ref,
                    receipt.raw_artifact_sha256,
                    receipt.raw_artifact_size_bytes,
                    raw_bytes,
                    receipt.raw_storage_manifest_id,
                    receipt.repository_manifest_id,
                    receipt.commit_receipt_id,
                ),
            )
        except sqlite3.IntegrityError as error:
            raise ConcurrentModification("M8 notification raw append was rejected") from error

    def _insert_notification(
        self,
        connection: sqlite3.Connection,
        receipt: M8NotificationCommitReceiptV1,
    ) -> None:
        event = receipt.audit_event
        authority = event.notification_authority
        plan = authority.plan
        try:
            connection.execute(
                """
                INSERT INTO m8_notification_versions(
                    notification_id, notification_version, status, case_id, case_version,
                    target_actor_id, target_channel, target_authority_revision,
                    target_authority_id, plan_authority_id, notification_authority_id,
                    notification_document_sha256, prior_notification_document_sha256,
                    transition_command_id, initiator_authority_id,
                    resolved_actor_document_sha256, dispatch_result_id,
                    delivery_receipt_id, reply_authority_id, raw_artifact_count,
                    raw_artifact_inventory_sha256, total_raw_artifact_size_bytes,
                    audit_event_id, audit_event_sha256, prior_audit_event_sha256,
                    repository_manifest_id, commit_receipt_id, notification_json,
                    audit_event_json, commit_receipt_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                          ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    receipt.notification_id,
                    receipt.notification_version,
                    receipt.status.value,
                    plan.case_id,
                    plan.case_version,
                    plan.target.actor_id,
                    plan.target.channel.value,
                    plan.target.authority_revision,
                    plan.target.target_authority_id,
                    plan.notification_id,
                    receipt.notification_authority_id,
                    receipt.notification_document_sha256,
                    authority.prior_notification_document_sha256,
                    authority.last_transition_command_id,
                    authority.last_initiator_authority_id,
                    event.resolved_actor_document_sha256,
                    authority.last_dispatch_result_id,
                    authority.last_delivery_receipt_id,
                    authority.last_reply_authority_id,
                    len(receipt.raw_artifact_receipts),
                    receipt.raw_artifact_inventory_sha256,
                    receipt.total_raw_artifact_size_bytes,
                    receipt.audit_event_id,
                    receipt.audit_event_sha256,
                    event.prior_audit_event_sha256,
                    receipt.repository_manifest_id,
                    receipt.commit_receipt_id,
                    canonical_json(authority.model_dump(mode="json")),
                    canonical_json(event.model_dump(mode="json")),
                    canonical_json(receipt.model_dump(mode="json")),
                ),
            )
            connection.executemany(
                """
                INSERT INTO m8_notification_version_raw_artifacts(
                    notification_id, notification_version, position, raw_artifact_ref
                ) VALUES (?, ?, ?, ?)
                """,
                tuple(
                    (
                        receipt.notification_id,
                        receipt.notification_version,
                        position,
                        item.raw_artifact_ref,
                    )
                    for position, item in enumerate(receipt.raw_artifact_receipts)
                ),
            )
        except sqlite3.IntegrityError as error:
            raise ConcurrentModification("M8 notification append was rejected") from error

    def _validated_raw_bytes(self, row: sqlite3.Row) -> bytes:
        value = row["raw_artifact_bytes"]
        if not isinstance(value, bytes):
            raise RepositoryIntegrityError("M8 notification raw column must contain bytes")
        if not 1 <= len(value) <= MAX_M8_NOTIFICATION_RAW_ARTIFACT_BYTES:
            raise RepositoryIntegrityError("M8 notification raw byte size is invalid")
        if len(value) != _row_int(row, "raw_artifact_size_bytes"):
            raise RepositoryIntegrityError("M8 notification raw byte size conflicts with index")
        if hashlib.sha256(value).hexdigest() != _row_str(row, "raw_artifact_sha256"):
            raise RepositoryIntegrityError("M8 notification raw byte hash is invalid")
        if _row_str(row, "repository_manifest_id") != self._repository_manifest_id:
            raise RepositoryIntegrityError("M8 notification raw repository manifest is invalid")
        return value

    def _validate_raw_row(
        self,
        row: sqlite3.Row,
        receipt: M8NotificationRawArtifactCommitReceiptV1,
    ) -> bytes:
        value = self._validated_raw_bytes(row)
        if (
            receipt.raw_artifact_ref != _row_str(row, "raw_artifact_ref")
            or receipt.raw_artifact_sha256 != _row_str(row, "raw_artifact_sha256")
            or receipt.raw_artifact_size_bytes != _row_int(row, "raw_artifact_size_bytes")
            or receipt.raw_storage_manifest_id != _row_str(row, "raw_storage_manifest_id")
            or receipt.repository_manifest_id != _row_str(row, "repository_manifest_id")
            or receipt.commit_receipt_id != _row_str(row, "raw_commit_receipt_id")
        ):
            raise RepositoryIntegrityError("M8 notification raw metadata conflicts with receipt")
        return value

    @staticmethod
    def _verify_retry_raw(
        receipt: M8NotificationCommitReceiptV1,
        raw_artifacts: tuple[bytes, ...],
        raw_storage_manifest_id: str,
    ) -> None:
        if len(receipt.raw_artifact_receipts) != len(raw_artifacts):
            raise ConcurrentModification("M8 notification retry raw inventory conflicts")
        for raw_receipt, raw_bytes in zip(
            receipt.raw_artifact_receipts,
            raw_artifacts,
            strict=True,
        ):
            if (
                raw_receipt.raw_storage_manifest_id != raw_storage_manifest_id
                or len(raw_bytes) != raw_receipt.raw_artifact_size_bytes
                or hashlib.sha256(raw_bytes).hexdigest() != raw_receipt.raw_artifact_sha256
            ):
                raise ConcurrentModification("M8 notification retry raw bytes conflict")


__all__ = ["SQLiteM8NotificationRepository"]
