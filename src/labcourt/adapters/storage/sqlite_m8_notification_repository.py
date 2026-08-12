"""SQLite-backed M8 notification targets, outbox lifecycle, audit, and raw bytes."""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path

from pydantic import ValidationError

from labcourt.application.m8_notification_workflow import (
    build_notification_plan_commit,
    build_notification_target_commit,
    build_notification_transition_commit,
)
from labcourt.contracts.canonical import canonical_json
from labcourt.contracts.frames import Sha256Hex
from labcourt.contracts.m8_access_cases import M8AuthorityReference
from labcourt.contracts.m8_case_persistence import (
    M8ActorAuthorityCommitReceiptV1,
    M8OperationalCaseCommitReceiptV1,
)
from labcourt.contracts.m8_notification_dispatch_claims import (
    M8NotificationDispatchCallFenceReceiptV1,
    M8NotificationDispatchClaimReceiptV1,
    M8NotificationDispatchClaimStatusV1,
    M8NotificationDispatchCompletionReceiptV1,
)
from labcourt.contracts.m8_notification_lifecycle import (
    M8NotificationAction,
    M8NotificationDispatchDisposition,
    M8NotificationDispatchRequestV1,
    M8NotificationDispatchResultV1,
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
        "m8_notification_dispatch_claims",
        "idx_m8_notification_dispatch_claims_source",
        "m8_notification_dispatch_call_fences",
        "m8_notification_dispatch_completions",
        "m8_notification_dispatch_claims_validate_current",
        "m8_notification_dispatch_call_fences_validate_current",
        "m8_notification_dispatch_completions_validate_transition",
        "m8_notification_dispatch_claims_no_update",
        "m8_notification_dispatch_claims_no_delete",
        "m8_notification_dispatch_claims_no_replace",
        "m8_notification_dispatch_call_fences_no_update",
        "m8_notification_dispatch_call_fences_no_delete",
        "m8_notification_dispatch_call_fences_no_replace",
        "m8_notification_dispatch_completions_no_update",
        "m8_notification_dispatch_completions_no_delete",
        "m8_notification_dispatch_completions_no_replace",
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


def _require_utc(value: datetime, name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"M8 notification {name} must be timezone-aware UTC")
    return value


def _canonical_utc(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _worker_owner_sha256(worker_owner_token: bytes) -> Sha256Hex:
    if not isinstance(worker_owner_token, bytes) or not 32 <= len(worker_owner_token) <= 256:
        raise ValueError("M8 notification worker owner token must be 32 through 256 bytes")
    return hashlib.sha256(worker_owner_token).hexdigest()


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
                WHERE version IN (1, 2, 3, 4, 8) ORDER BY version
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
            (8, "m8_notification_dispatch_claims"),
        ):
            raise RepositoryIntegrityError(
                "M8 notification migrations 0001-0004 and 0008 are not installed"
            )
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

    def claim_dispatch(
        self,
        request: M8NotificationDispatchRequestV1,
        worker_owner_token: bytes,
        lease_expires_at: datetime,
        claim_manifest_id: str,
    ) -> M8NotificationDispatchClaimReceiptV1:
        if not isinstance(request, M8NotificationDispatchRequestV1):
            raise TypeError("M8 notification dispatch claim requires a typed request")
        owner_sha256 = _worker_owner_sha256(worker_owner_token)
        expiry = _require_utc(lease_expires_at, "dispatch claim lease_expires_at")
        claim_manifest = _validate_sha256(claim_manifest_id, "dispatch claim manifest")
        try:
            candidate = M8NotificationDispatchClaimReceiptV1(
                request=request,
                worker_owner_sha256=owner_sha256,
                claimed_at=request.dispatched_at,
                lease_expires_at=expiry,
                claim_manifest_id=claim_manifest,
                repository_manifest_id=self._repository_manifest_id,
            )
        except ValueError as error:
            raise ConcurrentModification(str(error)) from error
        with self._immediate() as connection:
            existing_row = connection.execute(
                """
                SELECT * FROM m8_notification_dispatch_claims
                WHERE notification_id = ? AND source_notification_version = ?
                """,
                (candidate.notification_id, candidate.source_notification_version),
            ).fetchone()
            if existing_row is not None:
                existing = self._load_dispatch_claim_row(existing_row)
                if existing == candidate:
                    return existing
                raise ConcurrentModification(
                    "M8 notification source version already has a dispatch claim"
                )
            before = self._load_current_notification_for_write(
                connection,
                candidate.notification_id,
            )
            expected_source = (
                before.notification_version,
                before.notification_document_sha256,
                before.status,
                before.audit_event.notification_authority.plan,
            )
            observed_source = (
                request.source_notification_version,
                request.source_notification_authority_sha256,
                request.source_status,
                request.plan,
            )
            if expected_source != observed_source or before.status != M8NotificationStatus.QUEUED:
                raise ConcurrentModification(
                    "M8 dispatch claim does not bind the current QUEUED notification"
                )
            self._insert_dispatch_claim(connection, candidate)
            return candidate

    def fence_dispatch_call(
        self,
        claim_id: str,
        worker_owner_token: bytes,
        dispatch_authorization_id: str,
        fenced_at: datetime,
        call_fence_manifest_id: str,
    ) -> M8NotificationDispatchCallFenceReceiptV1:
        claim_reference = _validate_sha256(claim_id, "dispatch claim_id")
        owner_sha256 = _worker_owner_sha256(worker_owner_token)
        authorization = _validate_sha256(
            dispatch_authorization_id,
            "dispatch authorization",
        )
        fence_time = _require_utc(fenced_at, "dispatch call fenced_at")
        fence_manifest = _validate_sha256(
            call_fence_manifest_id,
            "dispatch call fence manifest",
        )
        with self._immediate() as connection:
            claim = self._load_dispatch_claim_by_id(connection, claim_reference)
            if claim.worker_owner_sha256 != owner_sha256:
                raise ConcurrentModification("M8 dispatch claim belongs to another worker")
            existing = connection.execute(
                "SELECT 1 FROM m8_notification_dispatch_call_fences WHERE claim_id = ?",
                (claim.claim_id,),
            ).fetchone()
            if existing is not None:
                raise ConcurrentModification(
                    "M8 dispatch claim already crossed the one-shot call boundary"
                )
            before = self._load_current_notification_for_write(connection, claim.notification_id)
            if (
                before.notification_version != claim.source_notification_version
                or before.notification_document_sha256
                != claim.request.source_notification_authority_sha256
                or before.status != M8NotificationStatus.QUEUED
            ):
                raise ConcurrentModification(
                    "M8 dispatch call fence no longer owns the current notification"
                )
            try:
                candidate = M8NotificationDispatchCallFenceReceiptV1(
                    claim=claim,
                    dispatch_authorization_id=authorization,
                    fenced_at=fence_time,
                    call_fence_manifest_id=fence_manifest,
                    repository_manifest_id=self._repository_manifest_id,
                )
            except ValueError as error:
                raise ConcurrentModification(str(error)) from error
            self._insert_dispatch_call_fence(connection, candidate)
            return candidate

    def complete_dispatch(
        self,
        claim_id: str,
        call_fence_id: str,
        worker_owner_token: bytes,
        dispatch_result: M8NotificationDispatchResultV1,
        raw_artifacts: tuple[bytes, ...],
        raw_storage_manifest_id: str,
        supporting_authorities: tuple[M8AuthorityReference, ...],
        command_manifest_id: str,
        audit_manifest_id: str,
        committed_at: datetime,
        completion_manifest_id: str,
    ) -> M8NotificationDispatchCompletionReceiptV1:
        claim_reference = _validate_sha256(claim_id, "dispatch claim_id")
        fence_reference = _validate_sha256(call_fence_id, "dispatch call_fence_id")
        owner_sha256 = _worker_owner_sha256(worker_owner_token)
        if not isinstance(dispatch_result, M8NotificationDispatchResultV1):
            raise TypeError("M8 dispatch completion requires a typed result")
        if not isinstance(raw_artifacts, tuple) or any(
            not isinstance(item, bytes) for item in raw_artifacts
        ):
            raise TypeError("M8 dispatch completion raw artifacts must be exact bytes")
        if not isinstance(supporting_authorities, tuple) or any(
            not isinstance(item, M8AuthorityReference) for item in supporting_authorities
        ):
            raise TypeError("M8 dispatch completion requires typed supporting authorities")
        raw_manifest = _validate_sha256(
            raw_storage_manifest_id,
            "dispatch raw storage manifest",
        )
        command_manifest = _validate_sha256(
            command_manifest_id,
            "dispatch command manifest",
        )
        audit_manifest = _validate_sha256(audit_manifest_id, "dispatch audit manifest")
        completion_time = _require_utc(committed_at, "dispatch completion committed_at")
        completion_manifest = _validate_sha256(
            completion_manifest_id,
            "dispatch completion manifest",
        )
        with self._immediate() as connection:
            claim = self._load_dispatch_claim_by_id(connection, claim_reference)
            if claim.worker_owner_sha256 != owner_sha256:
                raise ConcurrentModification("M8 dispatch claim belongs to another worker")
            fence = self._load_dispatch_call_fence_by_claim(connection, claim.claim_id)
            if fence.call_fence_id != fence_reference:
                raise ConcurrentModification("M8 dispatch completion uses another call fence")
            existing_row = connection.execute(
                "SELECT * FROM m8_notification_dispatch_completions WHERE claim_id = ?",
                (claim.claim_id,),
            ).fetchone()
            if existing_row is not None:
                existing = self._load_dispatch_completion_row(connection, existing_row)
                transition = existing.notification_commit.audit_event.transition_command
                if (
                    existing.dispatch_result == dispatch_result
                    and existing.committed_at == completion_time
                    and existing.completion_manifest_id == completion_manifest
                    and transition is not None
                    and transition.supporting_authorities == supporting_authorities
                    and transition.command_manifest_id == command_manifest
                    and existing.notification_commit.audit_event.audit_manifest_id == audit_manifest
                ):
                    self._verify_retry_raw(
                        existing.notification_commit,
                        raw_artifacts,
                        raw_manifest,
                    )
                    return existing
                raise ConcurrentModification(
                    "M8 dispatch claim already completed with different authority"
                )
            if dispatch_result.request != claim.request:
                raise ConcurrentModification("M8 dispatch result belongs to another claim")
            before = self._load_current_notification_for_write(connection, claim.notification_id)
            if (
                before.notification_version != claim.source_notification_version
                or before.notification_document_sha256
                != claim.request.source_notification_authority_sha256
                or before.status != M8NotificationStatus.QUEUED
            ):
                raise ConcurrentModification(
                    "M8 dispatch completion no longer owns the current notification"
                )
            try:
                command = M8NotificationTransitionCommandV1(
                    notification_id=claim.notification_id,
                    source_notification_version=claim.source_notification_version,
                    source_notification_authority_sha256=(
                        claim.request.source_notification_authority_sha256
                    ),
                    source_status=M8NotificationStatus.QUEUED,
                    action=(
                        M8NotificationAction.RECORD_SENT
                        if dispatch_result.disposition == M8NotificationDispatchDisposition.ACCEPTED
                        else M8NotificationAction.RECORD_FAILED
                    ),
                    initiator_kind=M8NotificationInitiatorKind.CHANNEL_ADAPTER,
                    dispatch_result=dispatch_result,
                    supporting_authorities=supporting_authorities,
                    explicit_human_confirmation=False,
                    occurred_at=dispatch_result.completed_at,
                    command_manifest_id=command_manifest,
                )
                notification_commit = build_notification_transition_commit(
                    before,
                    command,
                    raw_artifacts,
                    raw_manifest,
                    None,
                    audit_manifest,
                    self._repository_manifest_id,
                )
                completion = M8NotificationDispatchCompletionReceiptV1(
                    claim=claim,
                    call_fence=fence,
                    dispatch_result=dispatch_result,
                    notification_commit=notification_commit,
                    committed_at=completion_time,
                    completion_manifest_id=completion_manifest,
                    repository_manifest_id=self._repository_manifest_id,
                )
            except ValueError as error:
                raise ConcurrentModification(str(error)) from error
            for raw_receipt, raw_bytes in zip(
                notification_commit.raw_artifact_receipts,
                raw_artifacts,
                strict=True,
            ):
                self._insert_or_verify_raw(connection, raw_receipt, raw_bytes)
            self._insert_notification(connection, notification_commit)
            self._insert_dispatch_completion(connection, completion)
            return completion

    def get_dispatch_claim_status(
        self,
        claim_id: str,
        assessed_at: datetime,
    ) -> M8NotificationDispatchClaimStatusV1:
        claim_reference = _validate_sha256(claim_id, "dispatch claim_id")
        assessment_time = _require_utc(assessed_at, "dispatch claim assessed_at")
        with self._read() as connection:
            claim = self._load_dispatch_claim_by_id(connection, claim_reference)
            return self._load_dispatch_claim_status(connection, claim, assessment_time)

    def get_dispatch_claim_status_for_source(
        self,
        notification_id: str,
        source_notification_version: int,
        assessed_at: datetime,
    ) -> M8NotificationDispatchClaimStatusV1:
        require_reference_token(notification_id, "M8 notification dispatch source")
        if (
            not isinstance(source_notification_version, int)
            or isinstance(source_notification_version, bool)
            or source_notification_version < 1
        ):
            raise ValueError("M8 notification dispatch source version must be positive")
        assessment_time = _require_utc(assessed_at, "dispatch claim assessed_at")
        with self._read() as connection:
            row = connection.execute(
                """
                SELECT * FROM m8_notification_dispatch_claims
                WHERE notification_id = ? AND source_notification_version = ?
                """,
                (notification_id, source_notification_version),
            ).fetchone()
            if row is None:
                raise EvidenceMissing("M8 notification dispatch claim was not found")
            claim = self._load_dispatch_claim_row(row)
            return self._load_dispatch_claim_status(connection, claim, assessment_time)

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

    def _load_current_notification_for_write(
        self,
        connection: sqlite3.Connection,
        notification_id: str,
    ) -> M8NotificationCommitReceiptV1:
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

    def _load_dispatch_claim_by_id(
        self,
        connection: sqlite3.Connection,
        claim_id: str,
    ) -> M8NotificationDispatchClaimReceiptV1:
        row = connection.execute(
            "SELECT * FROM m8_notification_dispatch_claims WHERE claim_id = ?",
            (claim_id,),
        ).fetchone()
        if row is None:
            raise EvidenceMissing("M8 notification dispatch claim was not found")
        return self._load_dispatch_claim_row(row)

    def _load_dispatch_claim_row(
        self,
        row: sqlite3.Row,
    ) -> M8NotificationDispatchClaimReceiptV1:
        raw = _row_str(row, "receipt_json")
        try:
            receipt = M8NotificationDispatchClaimReceiptV1.model_validate_json(raw)
        except ValidationError as error:
            raise RepositoryIntegrityError(
                "persisted M8 notification dispatch claim is invalid"
            ) from error
        if (
            canonical_json(receipt.model_dump(mode="json")) != raw
            or receipt.claim_id != _row_str(row, "claim_id")
            or receipt.notification_id != _row_str(row, "notification_id")
            or receipt.source_notification_version != _row_int(row, "source_notification_version")
            or receipt.attempt_number != _row_int(row, "attempt_number")
            or receipt.request.dispatch_request_id != _row_str(row, "dispatch_request_id")
            or receipt.worker_owner_sha256 != _row_str(row, "worker_owner_sha256")
            or _canonical_utc(receipt.claimed_at) != _row_str(row, "claimed_at")
            or _canonical_utc(receipt.lease_expires_at) != _row_str(row, "lease_expires_at")
            or receipt.claim_manifest_id != _row_str(row, "claim_manifest_id")
            or receipt.repository_manifest_id != self._repository_manifest_id
            or receipt.repository_manifest_id != _row_str(row, "repository_manifest_id")
        ):
            raise RepositoryIntegrityError(
                "M8 notification dispatch claim index conflicts with receipt"
            )
        return receipt

    def _load_dispatch_call_fence_by_claim(
        self,
        connection: sqlite3.Connection,
        claim_id: str,
    ) -> M8NotificationDispatchCallFenceReceiptV1:
        row = connection.execute(
            "SELECT * FROM m8_notification_dispatch_call_fences WHERE claim_id = ?",
            (claim_id,),
        ).fetchone()
        if row is None:
            raise EvidenceMissing("M8 notification dispatch call fence was not found")
        return self._load_dispatch_call_fence_row(row)

    def _load_dispatch_call_fence_row(
        self,
        row: sqlite3.Row,
    ) -> M8NotificationDispatchCallFenceReceiptV1:
        raw = _row_str(row, "receipt_json")
        try:
            receipt = M8NotificationDispatchCallFenceReceiptV1.model_validate_json(raw)
        except ValidationError as error:
            raise RepositoryIntegrityError(
                "persisted M8 notification dispatch call fence is invalid"
            ) from error
        if (
            canonical_json(receipt.model_dump(mode="json")) != raw
            or receipt.call_fence_id != _row_str(row, "call_fence_id")
            or receipt.claim.claim_id != _row_str(row, "claim_id")
            or receipt.dispatch_authorization_id != _row_str(row, "dispatch_authorization_id")
            or _canonical_utc(receipt.fenced_at) != _row_str(row, "fenced_at")
            or receipt.call_fence_manifest_id != _row_str(row, "call_fence_manifest_id")
            or receipt.repository_manifest_id != self._repository_manifest_id
            or receipt.repository_manifest_id != _row_str(row, "repository_manifest_id")
        ):
            raise RepositoryIntegrityError(
                "M8 notification dispatch call fence index conflicts with receipt"
            )
        return receipt

    def _load_dispatch_completion_row(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> M8NotificationDispatchCompletionReceiptV1:
        raw = _row_str(row, "receipt_json")
        try:
            receipt = M8NotificationDispatchCompletionReceiptV1.model_validate_json(raw)
        except ValidationError as error:
            raise RepositoryIntegrityError(
                "persisted M8 notification dispatch completion is invalid"
            ) from error
        if (
            canonical_json(receipt.model_dump(mode="json")) != raw
            or receipt.completion_id != _row_str(row, "completion_id")
            or receipt.claim.claim_id != _row_str(row, "claim_id")
            or receipt.call_fence.call_fence_id != _row_str(row, "call_fence_id")
            or receipt.dispatch_result.dispatch_result_id != _row_str(row, "dispatch_result_id")
            or receipt.notification_commit.notification_id != _row_str(row, "notification_id")
            or receipt.notification_commit.notification_version
            != _row_int(row, "notification_version")
            or receipt.notification_commit.commit_receipt_id
            != _row_str(row, "notification_commit_receipt_id")
            or _canonical_utc(receipt.committed_at) != _row_str(row, "committed_at")
            or receipt.completion_manifest_id != _row_str(row, "completion_manifest_id")
            or receipt.repository_manifest_id != self._repository_manifest_id
            or receipt.repository_manifest_id != _row_str(row, "repository_manifest_id")
        ):
            raise RepositoryIntegrityError(
                "M8 notification dispatch completion index conflicts with receipt"
            )
        claim_row = connection.execute(
            "SELECT * FROM m8_notification_dispatch_claims WHERE claim_id = ?",
            (receipt.claim.claim_id,),
        ).fetchone()
        fence_row = connection.execute(
            "SELECT * FROM m8_notification_dispatch_call_fences WHERE call_fence_id = ?",
            (receipt.call_fence.call_fence_id,),
        ).fetchone()
        notification_row = connection.execute(
            """
            SELECT * FROM m8_notification_versions
            WHERE notification_id = ? AND notification_version = ?
            """,
            (
                receipt.notification_commit.notification_id,
                receipt.notification_commit.notification_version,
            ),
        ).fetchone()
        if (
            claim_row is None
            or fence_row is None
            or notification_row is None
            or self._load_dispatch_claim_row(claim_row) != receipt.claim
            or self._load_dispatch_call_fence_row(fence_row) != receipt.call_fence
            or self._load_notification_row(connection, notification_row)
            != receipt.notification_commit
        ):
            raise RepositoryIntegrityError(
                "M8 notification dispatch completion dependencies are incomplete"
            )
        return receipt

    def _load_dispatch_claim_status(
        self,
        connection: sqlite3.Connection,
        claim: M8NotificationDispatchClaimReceiptV1,
        assessed_at: datetime,
    ) -> M8NotificationDispatchClaimStatusV1:
        fence_row = connection.execute(
            "SELECT * FROM m8_notification_dispatch_call_fences WHERE claim_id = ?",
            (claim.claim_id,),
        ).fetchone()
        completion_row = connection.execute(
            "SELECT * FROM m8_notification_dispatch_completions WHERE claim_id = ?",
            (claim.claim_id,),
        ).fetchone()
        fence = self._load_dispatch_call_fence_row(fence_row) if fence_row is not None else None
        completion = (
            self._load_dispatch_completion_row(connection, completion_row)
            if completion_row is not None
            else None
        )
        try:
            return M8NotificationDispatchClaimStatusV1(
                claim=claim,
                call_fence=fence,
                completion=completion,
                assessed_at=assessed_at,
                repository_manifest_id=self._repository_manifest_id,
            )
        except ValueError as error:
            raise RepositoryIntegrityError(
                "persisted M8 notification dispatch status is invalid"
            ) from error

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

    def _insert_dispatch_claim(
        self,
        connection: sqlite3.Connection,
        receipt: M8NotificationDispatchClaimReceiptV1,
    ) -> None:
        try:
            connection.execute(
                """
                INSERT INTO m8_notification_dispatch_claims(
                    claim_id, notification_id, source_notification_version,
                    attempt_number, dispatch_request_id, worker_owner_sha256,
                    claimed_at, lease_expires_at, claim_manifest_id,
                    repository_manifest_id, receipt_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    receipt.claim_id,
                    receipt.notification_id,
                    receipt.source_notification_version,
                    receipt.attempt_number,
                    receipt.request.dispatch_request_id,
                    receipt.worker_owner_sha256,
                    _canonical_utc(receipt.claimed_at),
                    _canonical_utc(receipt.lease_expires_at),
                    receipt.claim_manifest_id,
                    receipt.repository_manifest_id,
                    canonical_json(receipt.model_dump(mode="json")),
                ),
            )
        except sqlite3.IntegrityError as error:
            raise ConcurrentModification("M8 dispatch claim append was rejected") from error

    def _insert_dispatch_call_fence(
        self,
        connection: sqlite3.Connection,
        receipt: M8NotificationDispatchCallFenceReceiptV1,
    ) -> None:
        try:
            connection.execute(
                """
                INSERT INTO m8_notification_dispatch_call_fences(
                    call_fence_id, claim_id, dispatch_authorization_id,
                    fenced_at, call_fence_manifest_id,
                    repository_manifest_id, receipt_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    receipt.call_fence_id,
                    receipt.claim.claim_id,
                    receipt.dispatch_authorization_id,
                    _canonical_utc(receipt.fenced_at),
                    receipt.call_fence_manifest_id,
                    receipt.repository_manifest_id,
                    canonical_json(receipt.model_dump(mode="json")),
                ),
            )
        except sqlite3.IntegrityError as error:
            raise ConcurrentModification("M8 dispatch call fence append was rejected") from error

    def _insert_dispatch_completion(
        self,
        connection: sqlite3.Connection,
        receipt: M8NotificationDispatchCompletionReceiptV1,
    ) -> None:
        notification = receipt.notification_commit
        try:
            connection.execute(
                """
                INSERT INTO m8_notification_dispatch_completions(
                    completion_id, claim_id, call_fence_id, dispatch_result_id,
                    notification_id, notification_version,
                    notification_commit_receipt_id, committed_at,
                    completion_manifest_id, repository_manifest_id, receipt_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    receipt.completion_id,
                    receipt.claim.claim_id,
                    receipt.call_fence.call_fence_id,
                    receipt.dispatch_result.dispatch_result_id,
                    notification.notification_id,
                    notification.notification_version,
                    notification.commit_receipt_id,
                    _canonical_utc(receipt.committed_at),
                    receipt.completion_manifest_id,
                    receipt.repository_manifest_id,
                    canonical_json(receipt.model_dump(mode="json")),
                ),
            )
        except sqlite3.IntegrityError as error:
            raise ConcurrentModification("M8 dispatch completion append was rejected") from error

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
