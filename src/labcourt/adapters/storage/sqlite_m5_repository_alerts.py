"""Transactional M5 alert policy, cooldown, outbox, and dispatch persistence."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import cast

from pydantic import ValidationError

from labcourt.application.m5_automatic_precedent import AutomaticPrecedentError
from labcourt.contracts.alert_policy import (
    MAX_ALERT_DISPATCH_ATTEMPTS,
    AlertChannelCapabilityAuthority,
    AlertCooldownAuthority,
    AlertCooldownKey,
    AlertDispatchAttempt,
    AlertDispatchContinuation,
    AlertDispatchDisposition,
    AlertDispatchFailureCode,
    AlertDispatchReceipt,
    AlertOutboxItem,
    AlertPolicyAuthority,
    AlertPolicyDisposition,
    ImmediateSafetyDeliveryAuthority,
)
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.cases import Case, TimelineEntry
from labcourt.contracts.enums import (
    ArtifactKind,
    AuditAction,
    CaseStatus,
    PrecedentSource,
    PrecedentStatus,
)
from labcourt.contracts.m5_precedent_usage import (
    M5PrecedentApplicationBatchAuthority,
    M5PrecedentApplicationCitationCommit,
)
from labcourt.contracts.m5_precedents import M5PrecedentAuthority
from labcourt.contracts.manifests import RunManifest, StreamManifest
from labcourt.contracts.references import require_reference_token
from labcourt.contracts.storage import ArtifactRef
from labcourt.domain.alert_policy import AlertPolicyError
from labcourt.exceptions import (
    ConcurrentModification,
    ContractViolation,
    ManifestMismatch,
)
from labcourt.ports.alert_policy import (
    ImmediateSafetyDeliveryDisabledError,
    ImmediateSafetyDeliveryFailureCode,
)
from labcourt.ports.evidence_repository import CaseSnapshot

from .sqlite_m3_repository_support import (
    _load_document,
    _require_sha256,
    _validated_copy,
)
from .sqlite_m5_repository_host import SQLiteM5RepositoryHost
from .sqlite_repository import (
    RepositoryIntegrityError,
    _audit_entry_from_row,
    _canonical_utc_timestamp,
    _document,
    _parse_utc_timestamp,
    _row_int,
    _row_optional_str,
    _row_str,
)

MAX_READY_ALERT_CASES = 256
MAX_PENDING_ALERT_OUTBOX = 256
ALERT_DISPATCH_LEASE_SECONDS = 60
MAX_AUTOMATIC_PRECEDENT_CLOCK_SKEW_SECONDS = 5


@dataclass(frozen=True, slots=True)
class _StoredCaseVersion:
    snapshot: CaseSnapshot
    document_sha256: str
    audit_sequence: int


@dataclass(frozen=True, slots=True)
class _StoredCooldown:
    authority: AlertCooldownAuthority
    revision: int


class SQLiteM5AlertRepository(SQLiteM5RepositoryHost):
    """M5 alert persistence mixed into the shared SQLite facade."""

    def list_ready_cases(
        self,
        run_id: str,
        limit: int,
    ) -> tuple[CaseSnapshot, ...]:
        require_reference_token(run_id, "M5 alert run_id")
        if (
            not isinstance(limit, int)
            or isinstance(limit, bool)
            or not 1 <= limit <= MAX_READY_ALERT_CASES
        ):
            raise ValueError(f"limit must be an integer in [1, {MAX_READY_ALERT_CASES}]")
        with self._read() as connection:
            self._load_run_manifest(connection, run_id)
            rows = connection.execute(
                """
                SELECT case_id FROM cases
                WHERE run_id = ? AND status = ?
                ORDER BY case_id
                LIMIT ?
                """,
                (run_id, CaseStatus.READY_FOR_ALERT_POLICY.value, limit),
            ).fetchall()
            snapshots = tuple(
                self._load_case(connection, run_id, _row_str(row, "case_id")) for row in rows
            )
        if any(snapshot.case.status != CaseStatus.READY_FOR_ALERT_POLICY for snapshot in snapshots):
            raise RepositoryIntegrityError("READY Case index returned a non-READY Case")
        return snapshots

    def load_current_cooldown(
        self,
        run_id: str,
        key: AlertCooldownKey,
        stream_id: str,
        stream_authority_sha256: str,
    ) -> AlertCooldownAuthority | None:
        require_reference_token(run_id, "M5 cooldown run_id")
        validated_key = self._validated_cooldown_key(key)
        require_reference_token(stream_id, "M5 cooldown stream_id")
        claimed_stream_sha256 = _require_sha256(
            stream_authority_sha256,
            "stream_authority_sha256",
        )
        with self._read() as connection:
            manifest = self._load_run_manifest(connection, run_id)
            self._require_stream_authority(
                manifest,
                camera_id=validated_key.camera_id,
                stream_id=stream_id,
                claimed_sha256=claimed_stream_sha256,
            )
            stored = self._load_current_cooldown_in_transaction(
                connection,
                run_id=run_id,
                key=validated_key,
                stream_id=stream_id,
                stream_authority_sha256=claimed_stream_sha256,
                manifest_id=manifest.manifest_id,
            )
            return stored.authority if stored is not None else None

    def record_immediate_safety_delivery(
        self,
        run_id: str,
        authority: ImmediateSafetyDeliveryAuthority,
    ) -> ImmediateSafetyDeliveryAuthority:
        del run_id, authority
        raise ImmediateSafetyDeliveryDisabledError(
            ImmediateSafetyDeliveryFailureCode.DISABLED_MISSING_CERTIFIED_SIGNAL_AUTHORITY
        )

    def load_immediate_safety_delivery(
        self,
        run_id: str,
        incident_id: str,
    ) -> ImmediateSafetyDeliveryAuthority | None:
        del run_id, incident_id
        raise ImmediateSafetyDeliveryDisabledError(
            ImmediateSafetyDeliveryFailureCode.DISABLED_MISSING_CERTIFIED_SIGNAL_AUTHORITY
        )

    def commit_alert_policy(
        self,
        run_id: str,
        expected_revision: int,
        authority: AlertPolicyAuthority,
        automatic_precedent: M5PrecedentAuthority,
        application_batch: M5PrecedentApplicationBatchAuthority | None = None,
        application_citations: tuple[M5PrecedentApplicationCitationCommit, ...] = (),
    ) -> CaseSnapshot:
        require_reference_token(run_id, "M5 alert commit run_id")
        self._require_alert_expected_revision(expected_revision)
        validated = self._validated_alert_authority(authority)
        validated_precedent = self._validated_precedent(automatic_precedent)
        validated_batch = self._validated_application_batch(application_batch)
        validated_citations = self._validated_application_citations(application_citations)
        if validated.request.run_id != run_id:
            raise ContractViolation("alert policy authority belongs to another run")

        try:
            with self._immediate() as connection:
                manifest = self._load_run_manifest(connection, run_id)
                collision = self._find_alert_collision(connection, run_id, validated)
                if collision is not None:
                    return self._replay_alert_commit(
                        connection,
                        row=collision,
                        run_id=run_id,
                        expected_revision=expected_revision,
                        authority=validated,
                        automatic_precedent=validated_precedent,
                        application_batch=validated_batch,
                        application_citations=validated_citations,
                        manifest=manifest,
                    )

                snapshot = self._load_case(
                    connection,
                    run_id,
                    validated.request.case_id,
                )
                if snapshot.revision != expected_revision:
                    raise ConcurrentModification(
                        f"case revision is {snapshot.revision}, expected {expected_revision}"
                    )
                if snapshot.case.status != CaseStatus.READY_FOR_ALERT_POLICY:
                    raise ConcurrentModification(
                        "new alert policy commit requires a READY_FOR_ALERT_POLICY Case"
                    )
                self._require_alert_scope(snapshot.case, validated, manifest)
                stream = self._require_stream_authority(
                    manifest,
                    camera_id=snapshot.case.event.camera_id,
                    stream_id=snapshot.case.event.stream_id,
                    claimed_sha256=validated.request.stream_authority_sha256,
                )
                current_cooldown = self._current_case_cooldown(
                    connection,
                    case=snapshot.case,
                    authority=validated,
                    stream=stream,
                    manifest=manifest,
                )
                current_emergency = self._current_emergency_delivery(
                    connection,
                    run_id=run_id,
                    requested=validated.request.prior_emergency_delivery,
                    manifest_id=manifest.manifest_id,
                )
                self._require_rebuilt_policy(
                    case=snapshot.case,
                    manifest=manifest,
                    prior_cooldown=current_cooldown,
                    prior_emergency_delivery=current_emergency,
                    proposed=validated,
                )
                self._require_rebuilt_automatic_precedent(
                    case=snapshot.case,
                    manifest=manifest,
                    alert_authority=validated,
                    proposed=validated_precedent,
                )
                usage = self._resolve_ready_precedent_usage_in_connection(
                    connection,
                    snapshot,
                )
                rebuilt_batch, rebuilt_citations = self._require_rebuilt_application_roots(
                    snapshot=snapshot,
                    usage=usage,
                    proposed_batch=validated_batch,
                    proposed_citations=validated_citations,
                    cited_at=validated_precedent.created_at,
                )
                self._require_automatic_precedent(
                    validated_precedent,
                    case=snapshot.case,
                    authority=validated,
                    manifest=manifest,
                )
                self._require_automatic_precedent_timestamp(
                    validated_precedent,
                    trusted_now=self._alert_repository_now(),
                )
                self._require_absent_automatic_precedent(
                    connection,
                    run_id=run_id,
                    authority=validated_precedent,
                    case_id=snapshot.case.case_id,
                )
                self._require_application_roots_absent(
                    connection,
                    run_id=run_id,
                    case_id=snapshot.case.case_id,
                )

                closed_case, object_ref = self._closed_case(snapshot.case, validated)
                head = self._validated_head(connection, run_id)
                committed = self._commit_m5_case_version(
                    connection,
                    previous=snapshot,
                    new_case=closed_case,
                    expected_head=head,
                    action=AuditAction.CASE_CLOSED,
                    object_ref=object_ref,
                )
                self._m5_fault("m5.alert.case_closed")
                self._insert_application_roots(
                    connection,
                    batch=rebuilt_batch,
                    citations=rebuilt_citations,
                    closing_case_revision=committed.revision,
                )
                self._require_stored_application_roots(
                    connection,
                    run_id=run_id,
                    case_id=snapshot.case.case_id,
                    expected_batch=rebuilt_batch,
                    expected_citations=rebuilt_citations,
                    closing_case_revision=committed.revision,
                )
                self._insert_alert_authority(
                    connection,
                    authority=validated,
                    source_case_revision=snapshot.revision,
                    closing_case_revision=committed.revision,
                )
                self._m5_fault("m5.alert.authority_inserted")
                if validated.cooldown_write is not None:
                    prior_revision = self._load_current_cooldown_revision(
                        connection,
                        run_id=run_id,
                        key_id=validated.cooldown_write.key.key_id,
                    )
                    self._insert_cooldown(
                        connection,
                        authority=validated,
                        revision=prior_revision + 1,
                    )
                    self._m5_fault("m5.alert.cooldown_inserted")
                if validated.outbox_item is not None:
                    self._insert_outbox(connection, validated)
                    self._m5_fault("m5.alert.outbox_inserted")
                inserted_precedent = self._insert_m5_precedent_authority(
                    connection,
                    validated_precedent,
                    None,
                    causal_fault_scope="m5.alert.automatic_precedent",
                )
                if inserted_precedent != validated_precedent:
                    raise RepositoryIntegrityError(
                        "automatic precedent insert returned another authority"
                    )
                self._m5_fault("m5.alert.automatic_precedent_inserted")
                return committed
        except sqlite3.IntegrityError as exc:
            raise RepositoryIntegrityError("alert policy commit violated SQLite authority") from exc

    def begin_dispatch(
        self,
        item: AlertOutboxItem,
        lease_owner_sha256: str,
        channel_capability: AlertChannelCapabilityAuthority,
    ) -> AlertDispatchAttempt | AlertDispatchReceipt:
        validated = self._validated_outbox(item)
        _require_sha256(lease_owner_sha256, "alert dispatch lease_owner_sha256")
        validated_capability = self._validated_channel_capability(channel_capability)
        try:
            with self._immediate() as connection:
                now = _parse_utc_timestamp(self._recorded_at(), "alert dispatch clock")
                row = connection.execute(
                    "SELECT * FROM alert_outbox WHERE run_id = ? AND outbox_id = ?",
                    (validated.run_id, validated.outbox_id),
                ).fetchone()
                if row is None:
                    raise ContractViolation("unknown alert outbox item")
                stored = self._outbox_from_row(row)
                if stored != validated:
                    raise RepositoryIntegrityError("alert outbox identity binds different content")
                rescinded = connection.execute(
                    """
                    SELECT 1 FROM alert_rescissions
                    WHERE run_id = ? AND alert_id = ?
                    """,
                    (stored.run_id, stored.alert.alert_id),
                ).fetchone()
                if rescinded is not None:
                    raise ContractViolation("rescinded alert cannot enter dispatch")
                self._require_outbox_close_authority(connection, row, stored)
                validated_capability = self._require_trusted_channel_capability(
                    connection,
                    run_id=stored.run_id,
                    proposed=validated_capability,
                )
                succeeded = self._load_successful_dispatch(
                    connection,
                    run_id=stored.run_id,
                    outbox_id=stored.outbox_id,
                )
                if succeeded is not None:
                    return succeeded

                attempts = self._load_dispatch_attempts(
                    connection,
                    run_id=stored.run_id,
                    outbox_id=stored.outbox_id,
                )
                attempt_number = len(attempts) + 1
                if attempts:
                    latest = attempts[-1]
                    existing = self._load_dispatch_receipt(
                        connection,
                        run_id=stored.run_id,
                        attempt_id=latest.attempt_id,
                    )
                    if existing is None:
                        if latest.lease_expires_at > now:
                            raise ConcurrentModification(
                                "alert dispatch outbox already has an active lease"
                            )
                        recovery = self._expired_dispatch_receipt(latest)
                        self._insert_dispatch_receipt(connection, stored.run_id, recovery)
                        self._m5_fault("m5.alert.dispatch_expiry_recorded")
                        if recovery.continuation == AlertDispatchContinuation.ATTENTION_REQUIRED:
                            return recovery
                        if latest.channel_capability != validated_capability:
                            return recovery
                    elif existing.continuation in {
                        AlertDispatchContinuation.CLOSED,
                        AlertDispatchContinuation.ATTENTION_REQUIRED,
                    }:
                        return existing
                    elif latest.channel_capability != validated_capability:
                        raise ContractViolation(
                            "alert dispatch retry cannot change channel capability authority"
                        )

                if attempt_number > MAX_ALERT_DISPATCH_ATTEMPTS:
                    raise RepositoryIntegrityError(
                        "alert dispatch exceeded its fixed attempt bound without terminal state"
                    )
                started_at = now
                lease_expires_at = now + timedelta(seconds=ALERT_DISPATCH_LEASE_SECONDS)
                try:
                    attempt = AlertDispatchAttempt(
                        outbox_id=stored.outbox_id,
                        alert_id=stored.alert.alert_id,
                        case_id=stored.case_id,
                        attempt_number=attempt_number,
                        fence=attempt_number,
                        lease_owner_sha256=lease_owner_sha256,
                        started_at=started_at,
                        lease_expires_at=lease_expires_at,
                        channel_capability=validated_capability,
                        idempotency_key=stored.alert.alert_id,
                    )
                except ValidationError as exc:
                    raise ContractViolation("invalid alert dispatch attempt") from exc
                attempt_json, document_sha256 = _document(attempt)
                connection.execute(
                    """
                    INSERT INTO alert_dispatch_attempts(
                        run_id, attempt_id, outbox_id, alert_id, case_id,
                        attempt_number, fence, lease_owner_sha256,
                        started_at, lease_expires_at, channel_capability_id,
                        idempotency_key,
                        attempt_json, document_sha256
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        stored.run_id,
                        attempt.attempt_id,
                        attempt.outbox_id,
                        attempt.alert_id,
                        attempt.case_id,
                        attempt.attempt_number,
                        attempt.fence,
                        attempt.lease_owner_sha256,
                        _canonical_utc_timestamp(attempt.started_at, "dispatch started_at"),
                        _canonical_utc_timestamp(
                            attempt.lease_expires_at,
                            "dispatch lease_expires_at",
                        ),
                        attempt.channel_capability.capability_id,
                        attempt.idempotency_key,
                        attempt_json,
                        document_sha256,
                    ),
                )
                self._m5_fault("m5.alert.dispatch_attempt_inserted")
                return attempt
        except sqlite3.IntegrityError as exc:
            raise RepositoryIntegrityError(
                "alert dispatch attempt violated SQLite authority"
            ) from exc

    def list_pending_outbox(
        self,
        run_id: str,
        limit: int,
    ) -> tuple[AlertOutboxItem, ...]:
        require_reference_token(run_id, "M5 pending outbox run_id")
        if (
            not isinstance(limit, int)
            or isinstance(limit, bool)
            or not 1 <= limit <= MAX_PENDING_ALERT_OUTBOX
        ):
            raise ValueError(f"limit must be an integer in [1, {MAX_PENDING_ALERT_OUTBOX}]")
        with self._read() as connection:
            self._load_run_manifest(connection, run_id)
            now_text = self._recorded_at()
            rows = connection.execute(
                """
                SELECT o.* FROM alert_outbox AS o
                WHERE o.run_id = ?
                  AND NOT EXISTS (
                      SELECT 1 FROM alert_dispatch_receipts AS r
                      WHERE r.run_id = o.run_id
                        AND r.outbox_id = o.outbox_id
                        AND r.disposition = ?
                  )
                  AND NOT EXISTS (
                      SELECT 1 FROM alert_dispatch_receipts AS terminal
                      WHERE terminal.run_id = o.run_id
                        AND terminal.outbox_id = o.outbox_id
                        AND terminal.continuation = ?
                  )
                  AND NOT EXISTS (
                      SELECT 1 FROM alert_rescissions AS x
                      WHERE x.run_id = o.run_id
                        AND x.alert_id = o.alert_id
                  )
                  AND NOT EXISTS (
                      SELECT 1
                      FROM alert_dispatch_attempts AS active
                      WHERE active.run_id = o.run_id
                        AND active.outbox_id = o.outbox_id
                        AND active.attempt_number = (
                            SELECT MAX(head.attempt_number)
                            FROM alert_dispatch_attempts AS head
                            WHERE head.run_id = o.run_id
                              AND head.outbox_id = o.outbox_id
                        )
                        AND active.lease_expires_at > ?
                        AND NOT EXISTS (
                            SELECT 1 FROM alert_dispatch_receipts AS closed
                            WHERE closed.run_id = active.run_id
                              AND closed.attempt_id = active.attempt_id
                        )
                  )
                ORDER BY
                    CASE o.priority
                        WHEN 'CRITICAL' THEN 0
                        WHEN 'HIGH' THEN 1
                        ELSE 2
                    END,
                    o.rowid
                LIMIT ?
                """,
                (
                    run_id,
                    AlertDispatchDisposition.SUCCEEDED.value,
                    AlertDispatchContinuation.ATTENTION_REQUIRED.value,
                    now_text,
                    limit,
                ),
            ).fetchall()
            items: list[AlertOutboxItem] = []
            for row in rows:
                item = self._outbox_from_row(row)
                self._require_outbox_close_authority(connection, row, item)
                items.append(item)
            return tuple(items)

    def complete_dispatch(
        self,
        attempt: AlertDispatchAttempt,
        receipt: AlertDispatchReceipt,
    ) -> AlertDispatchReceipt:
        validated_attempt = self._validated_dispatch_attempt(attempt)
        validated_receipt = self._validated_dispatch_receipt(receipt)
        if (
            validated_receipt.attempt_id != validated_attempt.attempt_id
            or validated_receipt.outbox_id != validated_attempt.outbox_id
            or validated_receipt.alert_id != validated_attempt.alert_id
            or validated_receipt.case_id != validated_attempt.case_id
            or validated_receipt.attempt_number != validated_attempt.attempt_number
            or validated_receipt.idempotency_key != validated_attempt.idempotency_key
        ):
            raise ContractViolation("dispatch receipt does not exactly bind its attempt")
        try:
            with self._immediate() as connection:
                rows = connection.execute(
                    "SELECT * FROM alert_dispatch_attempts WHERE attempt_id = ?",
                    (validated_attempt.attempt_id,),
                ).fetchall()
                if not rows:
                    raise ContractViolation("unknown alert dispatch attempt")
                if len(rows) != 1:
                    raise RepositoryIntegrityError(
                        "dispatch attempt identity is ambiguous across runs"
                    )
                row = rows[0]
                run_id = _row_str(row, "run_id")
                stored_attempt = self._dispatch_attempt_from_row(row)
                if stored_attempt != validated_attempt:
                    raise RepositoryIntegrityError(
                        "dispatch attempt identity binds different content"
                    )
                outbox_row = connection.execute(
                    "SELECT * FROM alert_outbox WHERE run_id = ? AND outbox_id = ?",
                    (run_id, stored_attempt.outbox_id),
                ).fetchone()
                if outbox_row is None:
                    raise RepositoryIntegrityError("dispatch attempt lost its outbox root")
                outbox = self._outbox_from_row(outbox_row)
                self._require_outbox_close_authority(connection, outbox_row, outbox)

                succeeded = self._load_successful_dispatch(
                    connection,
                    run_id=run_id,
                    outbox_id=stored_attempt.outbox_id,
                )
                if succeeded is not None:
                    existing_for_attempt = self._load_dispatch_receipt(
                        connection,
                        run_id=run_id,
                        attempt_id=stored_attempt.attempt_id,
                    )
                    if existing_for_attempt == validated_receipt:
                        return existing_for_attempt
                    raise ConcurrentModification(
                        "dispatch completion was superseded by a successful attempt"
                    )
                existing_row = connection.execute(
                    """
                    SELECT * FROM alert_dispatch_receipts
                    WHERE run_id = ? AND attempt_id = ?
                    """,
                    (run_id, stored_attempt.attempt_id),
                ).fetchone()
                if existing_row is not None:
                    existing = self._dispatch_receipt_from_row(existing_row)
                    if existing != validated_receipt:
                        raise RepositoryIntegrityError(
                            "dispatch attempt already binds another receipt"
                        )
                    return existing

                latest = connection.execute(
                    """
                    SELECT MAX(attempt_number) AS attempt_number
                    FROM alert_dispatch_attempts
                    WHERE run_id = ? AND outbox_id = ?
                    """,
                    (run_id, stored_attempt.outbox_id),
                ).fetchone()
                if latest is None or _row_int(latest, "attempt_number") != (
                    stored_attempt.attempt_number
                ):
                    raise ConcurrentModification(
                        "stale alert dispatch attempt was superseded by a newer fence"
                    )
                now = _parse_utc_timestamp(self._recorded_at(), "alert dispatch clock")
                if stored_attempt.lease_expires_at <= now:
                    raise ConcurrentModification(
                        "alert dispatch attempt lease expired before first completion"
                    )
                self._insert_dispatch_receipt(connection, run_id, validated_receipt)
                self._m5_fault("m5.alert.dispatch_receipt_inserted")
                return validated_receipt
        except sqlite3.IntegrityError as exc:
            raise RepositoryIntegrityError(
                "alert dispatch receipt violated SQLite authority"
            ) from exc

    @staticmethod
    def _validated_cooldown_key(value: AlertCooldownKey) -> AlertCooldownKey:
        if not isinstance(value, AlertCooldownKey):
            raise TypeError("key must be an AlertCooldownKey")
        return _validated_copy(value, AlertCooldownKey)

    @staticmethod
    def _validated_immediate_delivery(
        value: ImmediateSafetyDeliveryAuthority,
    ) -> ImmediateSafetyDeliveryAuthority:
        if not isinstance(value, ImmediateSafetyDeliveryAuthority):
            raise TypeError("authority must be an ImmediateSafetyDeliveryAuthority")
        return _validated_copy(value, ImmediateSafetyDeliveryAuthority)

    @staticmethod
    def _validated_alert_authority(value: AlertPolicyAuthority) -> AlertPolicyAuthority:
        if not isinstance(value, AlertPolicyAuthority):
            raise TypeError("authority must be an AlertPolicyAuthority")
        return _validated_copy(value, AlertPolicyAuthority)

    @staticmethod
    def _validated_precedent(value: M5PrecedentAuthority) -> M5PrecedentAuthority:
        if not isinstance(value, M5PrecedentAuthority):
            raise TypeError("automatic_precedent must be an M5PrecedentAuthority")
        return _validated_copy(value, M5PrecedentAuthority)

    @staticmethod
    def _validated_outbox(value: AlertOutboxItem) -> AlertOutboxItem:
        if not isinstance(value, AlertOutboxItem):
            raise TypeError("item must be an AlertOutboxItem")
        return _validated_copy(value, AlertOutboxItem)

    @staticmethod
    def _validated_dispatch_attempt(value: AlertDispatchAttempt) -> AlertDispatchAttempt:
        if not isinstance(value, AlertDispatchAttempt):
            raise TypeError("attempt must be an AlertDispatchAttempt")
        return _validated_copy(value, AlertDispatchAttempt)

    @staticmethod
    def _validated_channel_capability(
        value: AlertChannelCapabilityAuthority,
    ) -> AlertChannelCapabilityAuthority:
        if not isinstance(value, AlertChannelCapabilityAuthority):
            raise TypeError("channel_capability must be an AlertChannelCapabilityAuthority")
        return _validated_copy(value, AlertChannelCapabilityAuthority)

    def _require_trusted_channel_capability(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        proposed: AlertChannelCapabilityAuthority,
    ) -> AlertChannelCapabilityAuthority:
        trusted = self._alert_channel_capability
        if trusted is None:
            raise ContractViolation(
                "alert dispatch requires a composition-root channel capability authority"
            )
        if proposed != trusted:
            raise ContractViolation(
                "caller channel capability differs from the composition-root authority"
            )
        manifest = self._load_run_manifest(connection, run_id)
        if (
            trusted.run_id != run_id
            or trusted.manifest_id != manifest.manifest_id
            or trusted.config_sha256 != manifest.config_sha256
        ):
            raise ManifestMismatch(
                "alert channel capability differs from the run manifest/config authority"
            )

        rows = connection.execute(
            """
            SELECT * FROM alert_channel_capabilities
            WHERE run_id = ? AND (capability_id = ? OR channel = ?)
            """,
            (run_id, trusted.capability_id, trusted.channel),
        ).fetchall()
        if rows:
            if len(rows) != 1:
                raise RepositoryIntegrityError(
                    "alert channel capability resolves to multiple durable roots"
                )
            stored = self._channel_capability_from_row(rows[0])
            if stored != trusted:
                raise RepositoryIntegrityError(
                    "alert channel capability/channel binds different durable content"
                )
            return stored

        authority_json, document_sha256 = _document(trusted)
        connection.execute(
            """
            INSERT INTO alert_channel_capabilities(
                run_id, capability_id, channel, capability_revision,
                idempotency_guarantee, provider_idempotency_key,
                manifest_id, config_sha256, authority_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                trusted.run_id,
                trusted.capability_id,
                trusted.channel,
                trusted.capability_revision,
                trusted.idempotency_guarantee.value,
                trusted.provider_idempotency_key,
                trusted.manifest_id,
                trusted.config_sha256,
                authority_json,
                document_sha256,
            ),
        )
        self._m5_fault("m5.alert.channel_capability_inserted")
        return trusted

    @staticmethod
    def _channel_capability_from_row(
        row: sqlite3.Row,
    ) -> AlertChannelCapabilityAuthority:
        capability = _load_document(
            row,
            json_key="authority_json",
            sha256_key="document_sha256",
            model_type=AlertChannelCapabilityAuthority,
        )
        indexed = (
            _row_str(row, "run_id"),
            _row_str(row, "capability_id"),
            _row_str(row, "channel"),
            _row_str(row, "capability_revision"),
            _row_str(row, "idempotency_guarantee"),
            _row_optional_str(row, "provider_idempotency_key"),
            _row_str(row, "manifest_id"),
            _row_str(row, "config_sha256"),
        )
        expected = (
            capability.run_id,
            capability.capability_id,
            capability.channel,
            capability.capability_revision,
            capability.idempotency_guarantee.value,
            capability.provider_idempotency_key,
            capability.manifest_id,
            capability.config_sha256,
        )
        if indexed != expected:
            raise RepositoryIntegrityError(
                "alert channel capability indexes differ from canonical content"
            )
        return capability

    @staticmethod
    def _validated_dispatch_receipt(value: AlertDispatchReceipt) -> AlertDispatchReceipt:
        if not isinstance(value, AlertDispatchReceipt):
            raise TypeError("receipt must be an AlertDispatchReceipt")
        return _validated_copy(value, AlertDispatchReceipt)

    @staticmethod
    def _require_alert_expected_revision(expected_revision: int) -> None:
        if (
            not isinstance(expected_revision, int)
            or isinstance(expected_revision, bool)
            or expected_revision < 1
        ):
            raise ValueError("expected_revision must be a positive integer")

    @staticmethod
    def _require_stream_authority(
        manifest: RunManifest,
        *,
        camera_id: str,
        stream_id: str,
        claimed_sha256: str,
    ) -> StreamManifest:
        matches = tuple(
            stream
            for stream in manifest.streams
            if (stream.camera_id, stream.stream_id) == (camera_id, stream_id)
        )
        if len(matches) != 1:
            raise ManifestMismatch("alert stream is not pinned by the run manifest")
        stream = matches[0]
        expected = sha256_hex(["alert-stream-authority", 1, stream.model_dump(mode="json")])
        if claimed_sha256 != expected:
            raise ManifestMismatch("alert stream authority hash does not match the manifest")
        return stream

    def _load_current_cooldown_in_transaction(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        key: AlertCooldownKey,
        stream_id: str,
        stream_authority_sha256: str,
        manifest_id: str,
    ) -> _StoredCooldown | None:
        rows = connection.execute(
            """
            SELECT * FROM alert_cooldowns
            WHERE run_id = ? AND key_id = ?
            ORDER BY revision
            """,
            (run_id, key.key_id),
        ).fetchall()
        if not rows:
            return None
        revisions = tuple(_row_int(row, "revision") for row in rows)
        if revisions != tuple(range(1, len(rows) + 1)):
            raise RepositoryIntegrityError("alert cooldown revisions are not contiguous")
        row = rows[-1]
        authority = self._cooldown_from_row(
            row,
            run_id=run_id,
            manifest_id=manifest_id,
        )
        if authority.key != key:
            raise RepositoryIntegrityError("cooldown key index binds different content")
        if (
            authority.stream_id != stream_id
            or _row_str(row, "stream_authority_sha256") != stream_authority_sha256
        ):
            raise ManifestMismatch("current cooldown belongs to another pinned stream authority")
        return _StoredCooldown(authority=authority, revision=revisions[-1])

    @staticmethod
    def _cooldown_from_row(
        row: sqlite3.Row,
        *,
        run_id: str,
        manifest_id: str,
    ) -> AlertCooldownAuthority:
        authority = _load_document(
            row,
            json_key="authority_json",
            sha256_key="document_sha256",
            model_type=AlertCooldownAuthority,
        )
        indexed = (
            _row_str(row, "run_id"),
            _row_str(row, "key_id"),
            _row_str(row, "authority_id"),
            _row_str(row, "zone_id"),
            _row_str(row, "violation_type"),
            _row_str(row, "track_ref"),
            _row_str(row, "tracker_epoch"),
            _row_str(row, "stream_id"),
            _row_str(row, "source_alert_id"),
            _row_int(row, "source_trigger_frame"),
            _row_int(row, "cooldown_until_frame_exclusive"),
            _row_str(row, "manifest_id"),
        )
        expected = (
            run_id,
            authority.key.key_id,
            authority.authority_id,
            authority.key.zone_id,
            authority.key.violation_type.value,
            authority.key.track_ref,
            authority.key.tracker_epoch,
            authority.stream_id,
            authority.source_alert_id,
            authority.source_trigger_frame,
            authority.cooldown_until_frame_exclusive,
            manifest_id,
        )
        if indexed != expected:
            raise RepositoryIntegrityError("alert cooldown indexes differ from canonical content")
        return authority

    def _find_immediate_delivery_collision(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        authority: ImmediateSafetyDeliveryAuthority,
    ) -> ImmediateSafetyDeliveryAuthority | None:
        rows = connection.execute(
            """
            SELECT * FROM m5_immediate_safety_deliveries
            WHERE run_id = ? AND (
                authority_id = ? OR incident_id = ? OR delivery_idempotency_key = ?
            )
            """,
            (
                run_id,
                authority.authority_id,
                authority.incident.incident_id,
                authority.incident.delivery_idempotency_key,
            ),
        ).fetchall()
        if not rows:
            return None
        if len(rows) != 1:
            raise RepositoryIntegrityError(
                "immediate safety delivery collision resolves to multiple roots"
            )
        manifest = self._load_run_manifest(connection, run_id)
        return self._immediate_delivery_from_row(
            rows[0],
            run_id=run_id,
            manifest_id=manifest.manifest_id,
        )

    @staticmethod
    def _immediate_delivery_from_row(
        row: sqlite3.Row,
        *,
        run_id: str,
        manifest_id: str,
    ) -> ImmediateSafetyDeliveryAuthority:
        authority = _load_document(
            row,
            json_key="authority_json",
            sha256_key="document_sha256",
            model_type=ImmediateSafetyDeliveryAuthority,
        )
        incident = authority.incident
        receipt = authority.delivery_receipt
        indexed = (
            _row_str(row, "run_id"),
            _row_str(row, "authority_id"),
            _row_str(row, "incident_id"),
            _row_str(row, "signal_id"),
            _row_str(row, "zone_id"),
            _row_str(row, "delivery_idempotency_key"),
            _row_str(row, "delivery_alert_id"),
            _row_str(row, "delivery_channel"),
            _row_optional_str(row, "provider_receipt_ref"),
            _row_str(row, "manifest_id"),
        )
        expected = (
            run_id,
            authority.authority_id,
            incident.incident_id,
            incident.signal_id,
            incident.zone_id,
            incident.delivery_idempotency_key,
            receipt.alert_id,
            receipt.channel,
            receipt.provider_receipt_ref,
            manifest_id,
        )
        if indexed != expected:
            raise RepositoryIntegrityError(
                "immediate safety delivery indexes differ from canonical content"
            )
        return authority

    @staticmethod
    def _require_alert_scope(
        case: Case,
        authority: AlertPolicyAuthority,
        manifest: RunManifest,
    ) -> None:
        request = authority.request
        if (
            request.run_id != case.run_id
            or request.case_id != case.case_id
            or request.source_case_status != CaseStatus.READY_FOR_ALERT_POLICY
            or request.manifest_id != case.manifest_id
            or request.manifest_id != manifest.manifest_id
            or request.config_sha256 != manifest.config_sha256
            or request.camera_id != case.event.camera_id
            or request.stream_id != case.event.stream_id
        ):
            raise ManifestMismatch("alert policy request does not match current Case/run authority")

    def _current_case_cooldown(
        self,
        connection: sqlite3.Connection,
        *,
        case: Case,
        authority: AlertPolicyAuthority,
        stream: StreamManifest,
        manifest: RunManifest,
    ) -> AlertCooldownAuthority | None:
        track_ref = case.event.primary_track_ref
        if track_ref is None:
            current = None
        else:
            key = AlertCooldownKey(
                zone_id=case.event.zone_id,
                violation_type=case.event.violation_type,
                track_ref=track_ref,
            )
            stored = self._load_current_cooldown_in_transaction(
                connection,
                run_id=case.run_id,
                key=key,
                stream_id=stream.stream_id,
                stream_authority_sha256=authority.request.stream_authority_sha256,
                manifest_id=manifest.manifest_id,
            )
            current = stored.authority if stored is not None else None
        if authority.request.prior_cooldown != current:
            raise ConcurrentModification("alert policy cooldown snapshot is not current")
        return current

    def _current_emergency_delivery(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        requested: ImmediateSafetyDeliveryAuthority | None,
        manifest_id: str,
    ) -> ImmediateSafetyDeliveryAuthority | None:
        del connection, run_id, manifest_id
        if requested is None:
            return None
        raise ImmediateSafetyDeliveryDisabledError(
            ImmediateSafetyDeliveryFailureCode.DISABLED_MISSING_CERTIFIED_SIGNAL_AUTHORITY
        )

    def _require_rebuilt_policy(
        self,
        *,
        case: Case,
        manifest: RunManifest,
        prior_cooldown: AlertCooldownAuthority | None,
        prior_emergency_delivery: ImmediateSafetyDeliveryAuthority | None,
        proposed: AlertPolicyAuthority,
    ) -> None:
        verifier = self._alert_policy_verifier
        if verifier is None:
            raise ContractViolation("alert close commits require an AlertPolicyVerifier")
        try:
            rebuilt = verifier.rebuild(
                case,
                manifest,
                prior_cooldown,
                prior_emergency_delivery,
            )
        except (TypeError, ValueError, AlertPolicyError) as exc:
            raise ContractViolation("trusted alert policy reconstruction failed") from exc
        if not isinstance(rebuilt, AlertPolicyAuthority):
            raise ContractViolation("AlertPolicyVerifier must return an AlertPolicyAuthority")
        if rebuilt != proposed:
            raise ContractViolation("proposed alert authority differs from trusted reconstruction")

    def _require_rebuilt_automatic_precedent(
        self,
        *,
        case: Case,
        manifest: RunManifest,
        alert_authority: AlertPolicyAuthority,
        proposed: M5PrecedentAuthority,
    ) -> None:
        verifier = self._automatic_precedent_verifier
        if verifier is None:
            raise ContractViolation("alert close commits require an AutomaticPrecedentVerifier")
        try:
            rebuilt = verifier.rebuild(
                case,
                manifest,
                alert_authority,
                proposed.created_at,
            )
        except (TypeError, ValueError, AutomaticPrecedentError) as exc:
            raise ContractViolation("trusted automatic precedent reconstruction failed") from exc
        if not isinstance(rebuilt, M5PrecedentAuthority):
            raise ContractViolation(
                "AutomaticPrecedentVerifier must return an M5PrecedentAuthority"
            )
        if rebuilt != proposed:
            raise ContractViolation(
                "proposed automatic precedent differs from trusted reconstruction"
            )

    def _alert_repository_now(self) -> datetime:
        try:
            return datetime.strptime(
                self._recorded_at(),
                "%Y-%m-%dT%H:%M:%S.%fZ",
            ).replace(tzinfo=UTC)
        except ValueError as exc:
            raise RepositoryIntegrityError(
                "repository clock did not produce canonical UTC"
            ) from exc

    @staticmethod
    def _require_automatic_precedent_timestamp(
        precedent: M5PrecedentAuthority,
        *,
        trusted_now: datetime,
    ) -> None:
        drift_seconds = abs((precedent.created_at - trusted_now).total_seconds())
        if drift_seconds > MAX_AUTOMATIC_PRECEDENT_CLOCK_SKEW_SECONDS:
            raise ContractViolation("automatic precedent created_at differs from repository clock")

    @staticmethod
    def _require_automatic_precedent(
        precedent: M5PrecedentAuthority,
        *,
        case: Case,
        authority: AlertPolicyAuthority,
        manifest: RunManifest,
    ) -> None:
        root = precedent.precedent
        if (
            precedent.run_id != case.run_id
            or precedent.revision != 1
            or root.source != PrecedentSource.AUTOMATIC
            or root.status != PrecedentStatus.PROVISIONAL
            or root.source_case_id != case.case_id
            or root.decision_direction != authority.final_decision
            or root.evidence_class != case.event.evidence_class
            or root.violation_type != case.event.violation_type
            or root.rule_version != case.event.rule_version
            or root.rule_version != manifest.rule_version
            or root.citation_count != 0
        ):
            raise ContractViolation("automatic precedent does not exactly bind the closing Case")
        text_model_id = manifest.models["text_embedding"].model_manifest_id
        visual_model_id = manifest.models["visual_embedding"].model_manifest_id
        if precedent.text_embedding is not None and (
            precedent.text_embedding.request.model_manifest_id != text_model_id
        ):
            raise ManifestMismatch("automatic precedent text embedding is not manifest-pinned")
        if any(
            item.request.model_manifest_id != visual_model_id
            for item in precedent.visual_embeddings
        ):
            raise ManifestMismatch("automatic precedent visual embedding is not manifest-pinned")

    @staticmethod
    def _require_absent_automatic_precedent(
        connection: sqlite3.Connection,
        *,
        run_id: str,
        authority: M5PrecedentAuthority,
        case_id: str,
    ) -> None:
        row = connection.execute(
            """
            SELECT 1 FROM precedents
            WHERE run_id = ? AND (
                authority_id = ? OR precedent_id = ?
                OR (source = ? AND source_case_id = ? AND revision = 1)
            )
            LIMIT 1
            """,
            (
                run_id,
                authority.authority_id,
                authority.precedent.precedent_id,
                PrecedentSource.AUTOMATIC.value,
                case_id,
            ),
        ).fetchone()
        if row is not None:
            raise ConcurrentModification("closing Case already has a precedent authority")

    @staticmethod
    def _closed_case(
        case: Case,
        authority: AlertPolicyAuthority,
    ) -> tuple[Case, ArtifactRef]:
        decision = authority.decision
        alert_id = decision.alert_id if decision is not None else "NONE"
        if decision is None:
            object_ref = ArtifactRef(kind=ArtifactKind.CASE, artifact_id=case.case_id)
            alerts = case.alerts
        else:
            object_ref = ArtifactRef(kind=ArtifactKind.ALERT, artifact_id=decision.alert_id)
            alerts = (*case.alerts, decision)
        payload = case.model_dump(mode="json", exclude_computed_fields=True)
        payload.update(
            {
                "status": CaseStatus.CLOSED.value,
                "alerts": [item.model_dump(mode="json") for item in alerts],
                "final_decision": authority.final_decision.value,
                "timeline": [
                    *(entry.model_dump(mode="json") for entry in case.timeline),
                    TimelineEntry(
                        sequence=len(case.timeline),
                        action=AuditAction.CASE_CLOSED.value,
                        stage="ALERT_POLICY",
                        object_ref=object_ref.artifact_id,
                        details={
                            "alert_id": alert_id,
                            "disposition": authority.disposition.value,
                            "status": CaseStatus.CLOSED.value,
                        },
                    ).model_dump(mode="json"),
                ],
            }
        )
        try:
            return Case.model_validate(payload), object_ref
        except ValidationError as exc:
            raise ContractViolation("alert policy produced an invalid CLOSED Case") from exc

    @staticmethod
    def _insert_alert_authority(
        connection: sqlite3.Connection,
        *,
        authority: AlertPolicyAuthority,
        source_case_revision: int,
        closing_case_revision: int,
    ) -> None:
        authority_json, document_sha256 = _document(authority)
        request = authority.request
        decision = authority.decision
        connection.execute(
            """
            INSERT INTO alerts(
                run_id, authority_id, case_id,
                source_case_revision, closing_case_revision,
                policy_request_id, verdict_id, verdict_version,
                procedural_review_id, procedural_review_version,
                disposition, alert_id, final_decision,
                config_sha256, manifest_id, authority_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request.run_id,
                authority.authority_id,
                request.case_id,
                source_case_revision,
                closing_case_revision,
                request.request_id,
                request.verdict_id,
                request.verdict_version,
                request.procedural_review_id,
                request.procedural_review_version,
                authority.disposition.value,
                decision.alert_id if decision is not None else None,
                authority.final_decision.value,
                request.config_sha256,
                request.manifest_id,
                authority_json,
                document_sha256,
            ),
        )

    @staticmethod
    def _load_current_cooldown_revision(
        connection: sqlite3.Connection,
        *,
        run_id: str,
        key_id: str,
    ) -> int:
        row = connection.execute(
            """
            SELECT COALESCE(MAX(revision), 0) AS revision
            FROM alert_cooldowns WHERE run_id = ? AND key_id = ?
            """,
            (run_id, key_id),
        ).fetchone()
        if row is None:
            raise RepositoryIntegrityError("cooldown revision query returned no aggregate")
        return _row_int(row, "revision")

    @staticmethod
    def _insert_cooldown(
        connection: sqlite3.Connection,
        *,
        authority: AlertPolicyAuthority,
        revision: int,
    ) -> None:
        cooldown = authority.cooldown_write
        if cooldown is None:
            raise RepositoryIntegrityError("cooldown insert requires a cooldown authority")
        raw, document_sha256 = _document(cooldown)
        request = authority.request
        connection.execute(
            """
            INSERT INTO alert_cooldowns(
                run_id, key_id, revision, authority_id,
                zone_id, violation_type, track_ref, tracker_epoch,
                stream_id, stream_authority_sha256, source_alert_id,
                source_trigger_frame, cooldown_until_frame_exclusive,
                manifest_id, authority_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request.run_id,
                cooldown.key.key_id,
                revision,
                cooldown.authority_id,
                cooldown.key.zone_id,
                cooldown.key.violation_type.value,
                cooldown.key.track_ref,
                cooldown.key.tracker_epoch,
                cooldown.stream_id,
                request.stream_authority_sha256,
                cooldown.source_alert_id,
                cooldown.source_trigger_frame,
                cooldown.cooldown_until_frame_exclusive,
                request.manifest_id,
                raw,
                document_sha256,
            ),
        )

    @staticmethod
    def _insert_outbox(
        connection: sqlite3.Connection,
        authority: AlertPolicyAuthority,
    ) -> None:
        item = authority.outbox_item
        if item is None:
            raise RepositoryIntegrityError("outbox insert requires an outbox item")
        raw, document_sha256 = _document(item)
        connection.execute(
            """
            INSERT INTO alert_outbox(
                run_id, outbox_id, alert_authority_id, alert_id,
                case_id, case_authority_sha256, policy_request_id,
                priority, idempotency_key, manifest_id,
                outbox_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                item.run_id,
                item.outbox_id,
                authority.authority_id,
                item.alert.alert_id,
                item.case_id,
                item.case_authority_sha256,
                item.policy_request_id,
                item.priority.value,
                item.idempotency_key,
                item.manifest_id,
                raw,
                document_sha256,
            ),
        )

    @staticmethod
    def _find_alert_collision(
        connection: sqlite3.Connection,
        run_id: str,
        authority: AlertPolicyAuthority,
    ) -> sqlite3.Row | None:
        rows = connection.execute(
            """
            SELECT * FROM alerts
            WHERE run_id = ? AND (
                authority_id = ? OR case_id = ? OR policy_request_id = ?
            )
            """,
            (
                run_id,
                authority.authority_id,
                authority.request.case_id,
                authority.request.request_id,
            ),
        ).fetchall()
        if not rows:
            return None
        if len(rows) != 1:
            raise RepositoryIntegrityError("alert collision resolves to multiple roots")
        return cast(sqlite3.Row, rows[0])

    @staticmethod
    def _alert_authority_from_row(row: sqlite3.Row) -> AlertPolicyAuthority:
        authority = _load_document(
            row,
            json_key="authority_json",
            sha256_key="document_sha256",
            model_type=AlertPolicyAuthority,
        )
        request = authority.request
        decision = authority.decision
        indexed = (
            _row_str(row, "run_id"),
            _row_str(row, "authority_id"),
            _row_str(row, "case_id"),
            _row_str(row, "policy_request_id"),
            _row_str(row, "verdict_id"),
            _row_int(row, "verdict_version"),
            _row_str(row, "procedural_review_id"),
            _row_int(row, "procedural_review_version"),
            _row_str(row, "disposition"),
            _row_optional_str(row, "alert_id"),
            _row_str(row, "final_decision"),
            _row_str(row, "config_sha256"),
            _row_str(row, "manifest_id"),
        )
        expected = (
            request.run_id,
            authority.authority_id,
            request.case_id,
            request.request_id,
            request.verdict_id,
            request.verdict_version,
            request.procedural_review_id,
            request.procedural_review_version,
            authority.disposition.value,
            decision.alert_id if decision is not None else None,
            authority.final_decision.value,
            request.config_sha256,
            request.manifest_id,
        )
        if indexed != expected:
            raise RepositoryIntegrityError("alert indexes differ from canonical content")
        return authority

    def _replay_alert_commit(
        self,
        connection: sqlite3.Connection,
        *,
        row: sqlite3.Row,
        run_id: str,
        expected_revision: int,
        authority: AlertPolicyAuthority,
        automatic_precedent: M5PrecedentAuthority,
        application_batch: M5PrecedentApplicationBatchAuthority | None,
        application_citations: tuple[M5PrecedentApplicationCitationCommit, ...],
        manifest: RunManifest,
    ) -> CaseSnapshot:
        stored = self._alert_authority_from_row(row)
        if stored != authority:
            raise RepositoryIntegrityError("alert identity or Case already binds another authority")
        source_revision = _row_int(row, "source_case_revision")
        closing_revision = _row_int(row, "closing_case_revision")
        if expected_revision != source_revision or closing_revision != source_revision + 1:
            raise ConcurrentModification(
                "idempotent alert replay uses another source Case revision"
            )
        source = self._load_case_version_at(
            connection,
            run_id=run_id,
            case_id=authority.request.case_id,
            revision=source_revision,
        )
        closing = self._load_case_version_at(
            connection,
            run_id=run_id,
            case_id=authority.request.case_id,
            revision=closing_revision,
        )
        self._require_alert_scope(source.snapshot.case, authority, manifest)
        self._require_historical_alert_inputs(
            connection,
            authority=authority,
            manifest=manifest,
        )
        self._require_rebuilt_policy(
            case=source.snapshot.case,
            manifest=manifest,
            prior_cooldown=authority.request.prior_cooldown,
            prior_emergency_delivery=authority.request.prior_emergency_delivery,
            proposed=authority,
        )
        self._require_rebuilt_automatic_precedent(
            case=source.snapshot.case,
            manifest=manifest,
            alert_authority=authority,
            proposed=automatic_precedent,
        )
        usage = self._resolve_ready_precedent_usage_in_connection(
            connection,
            source.snapshot,
        )
        rebuilt_batch, rebuilt_citations = self._require_rebuilt_application_roots(
            snapshot=source.snapshot,
            usage=usage,
            proposed_batch=application_batch,
            proposed_citations=application_citations,
            cited_at=automatic_precedent.created_at,
        )
        self._require_automatic_precedent(
            automatic_precedent,
            case=source.snapshot.case,
            authority=authority,
            manifest=manifest,
        )
        expected_case, object_ref = self._closed_case(source.snapshot.case, authority)
        if closing.snapshot.case != expected_case:
            raise RepositoryIntegrityError("stored alert closing Case differs from its authority")
        closing_recorded_at = self._require_closing_audit(
            connection,
            source=source,
            closing=closing,
            object_ref=object_ref,
        )
        self._require_automatic_precedent_timestamp(
            automatic_precedent,
            trusted_now=closing_recorded_at,
        )
        self._require_alert_side_effect_roots(connection, row, authority)
        self._require_stored_automatic_precedent(
            connection,
            run_id=run_id,
            case_id=source.snapshot.case.case_id,
            expected=automatic_precedent,
        )
        self._require_stored_application_roots(
            connection,
            run_id=run_id,
            case_id=source.snapshot.case.case_id,
            expected_batch=rebuilt_batch,
            expected_citations=rebuilt_citations,
            closing_case_revision=closing_revision,
        )
        return closing.snapshot

    @staticmethod
    def _load_case_version_at(
        connection: sqlite3.Connection,
        *,
        run_id: str,
        case_id: str,
        revision: int,
    ) -> _StoredCaseVersion:
        row = connection.execute(
            """
            SELECT status, case_json, document_sha256, audit_sequence
            FROM case_versions
            WHERE run_id = ? AND case_id = ? AND revision = ?
            """,
            (run_id, case_id, revision),
        ).fetchone()
        if row is None:
            raise RepositoryIntegrityError("alert authority lost a Case version")
        case = _load_document(
            row,
            json_key="case_json",
            sha256_key="document_sha256",
            model_type=Case,
        )
        if (
            case.run_id != run_id
            or case.case_id != case_id
            or case.status.value != _row_str(row, "status")
        ):
            raise RepositoryIntegrityError(
                "alert Case version indexes differ from canonical content"
            )
        return _StoredCaseVersion(
            snapshot=CaseSnapshot(case=case, revision=revision),
            document_sha256=_row_str(row, "document_sha256"),
            audit_sequence=_row_int(row, "audit_sequence"),
        )

    def _require_historical_alert_inputs(
        self,
        connection: sqlite3.Connection,
        *,
        authority: AlertPolicyAuthority,
        manifest: RunManifest,
    ) -> None:
        request = authority.request
        self._require_stream_authority(
            manifest,
            camera_id=request.camera_id,
            stream_id=request.stream_id,
            claimed_sha256=request.stream_authority_sha256,
        )
        if request.prior_cooldown is not None:
            row = connection.execute(
                """
                SELECT * FROM alert_cooldowns
                WHERE run_id = ? AND authority_id = ?
                """,
                (request.run_id, request.prior_cooldown.authority_id),
            ).fetchone()
            if (
                row is None
                or self._cooldown_from_row(
                    row,
                    run_id=request.run_id,
                    manifest_id=manifest.manifest_id,
                )
                != request.prior_cooldown
            ):
                raise RepositoryIntegrityError("alert authority lost its prior cooldown root")
            if _row_str(row, "stream_authority_sha256") != request.stream_authority_sha256:
                raise RepositoryIntegrityError(
                    "prior cooldown stream authority differs from alert request"
                )
        if request.prior_emergency_delivery is not None:
            persisted = self._current_emergency_delivery(
                connection,
                run_id=request.run_id,
                requested=request.prior_emergency_delivery,
                manifest_id=manifest.manifest_id,
            )
            if persisted != request.prior_emergency_delivery:
                raise RepositoryIntegrityError("alert authority lost its emergency delivery root")

    @staticmethod
    def _require_closing_audit(
        connection: sqlite3.Connection,
        *,
        source: _StoredCaseVersion,
        closing: _StoredCaseVersion,
        object_ref: ArtifactRef,
    ) -> datetime:
        row = connection.execute(
            "SELECT * FROM audit_entries WHERE run_id = ? AND sequence = ?",
            (closing.snapshot.case.run_id, closing.audit_sequence),
        ).fetchone()
        if row is None:
            raise RepositoryIntegrityError("alert closing Case lost its audit entry")
        entry = _audit_entry_from_row(row)
        if (
            entry.action != AuditAction.CASE_CLOSED
            or entry.object_ref != object_ref
            or entry.before_sha256 != source.document_sha256
            or entry.after_sha256 != closing.document_sha256
        ):
            raise RepositoryIntegrityError("alert closing audit differs from the Case transition")
        try:
            return datetime.strptime(
                entry.recorded_at,
                "%Y-%m-%dT%H:%M:%S.%fZ",
            ).replace(tzinfo=UTC)
        except ValueError as exc:
            raise RepositoryIntegrityError(
                "alert closing audit timestamp is not canonical UTC"
            ) from exc

    def _require_alert_side_effect_roots(
        self,
        connection: sqlite3.Connection,
        alert_row: sqlite3.Row,
        authority: AlertPolicyAuthority,
    ) -> None:
        outbox_rows = connection.execute(
            "SELECT * FROM alert_outbox WHERE run_id = ? AND alert_authority_id = ?",
            (authority.request.run_id, authority.authority_id),
        ).fetchall()
        if authority.outbox_item is None:
            if outbox_rows:
                raise RepositoryIntegrityError(
                    "non-deliverable alert unexpectedly has an outbox root"
                )
        elif (
            len(outbox_rows) != 1 or self._outbox_from_row(outbox_rows[0]) != authority.outbox_item
        ):
            raise RepositoryIntegrityError("alert authority lost its exact outbox root")

        cooldown = authority.cooldown_write
        if cooldown is not None:
            row = connection.execute(
                """
                SELECT * FROM alert_cooldowns
                WHERE run_id = ? AND authority_id = ?
                """,
                (authority.request.run_id, cooldown.authority_id),
            ).fetchone()
            if (
                row is None
                or self._cooldown_from_row(
                    row,
                    run_id=authority.request.run_id,
                    manifest_id=authority.request.manifest_id,
                )
                != cooldown
            ):
                raise RepositoryIntegrityError("alert authority lost its exact cooldown write")
            if (
                _row_str(row, "stream_authority_sha256")
                != authority.request.stream_authority_sha256
            ):
                raise RepositoryIntegrityError("alert cooldown lost its stream authority binding")
        elif authority.disposition == AlertPolicyDisposition.ENQUEUE and (
            authority.request.primary_track_ref is not None
        ):
            raise RepositoryIntegrityError("tracked enqueue lost its cooldown authority")
        if _row_int(alert_row, "closing_case_revision") != (
            _row_int(alert_row, "source_case_revision") + 1
        ):
            raise RepositoryIntegrityError("alert Case revisions are not adjacent")

    def _require_stored_automatic_precedent(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        case_id: str,
        expected: M5PrecedentAuthority,
    ) -> None:
        rows = connection.execute(
            """
            SELECT * FROM precedents
            WHERE run_id = ? AND source = ? AND source_case_id = ? AND revision = 1
            """,
            (run_id, PrecedentSource.AUTOMATIC.value, case_id),
        ).fetchall()
        if len(rows) != 1:
            raise RepositoryIntegrityError(
                "closed Case does not have exactly one automatic precedent root"
            )
        stored = self._m5_authority_from_row(connection, rows[0])
        if stored != expected:
            raise RepositoryIntegrityError("automatic precedent root differs from close authority")

    @staticmethod
    def _outbox_from_row(row: sqlite3.Row) -> AlertOutboxItem:
        item = _load_document(
            row,
            json_key="outbox_json",
            sha256_key="document_sha256",
            model_type=AlertOutboxItem,
        )
        indexed = (
            _row_str(row, "run_id"),
            _row_str(row, "outbox_id"),
            _row_str(row, "alert_id"),
            _row_str(row, "case_id"),
            _row_str(row, "case_authority_sha256"),
            _row_str(row, "policy_request_id"),
            _row_str(row, "priority"),
            _row_str(row, "idempotency_key"),
            _row_str(row, "manifest_id"),
        )
        expected = (
            item.run_id,
            item.outbox_id,
            item.alert.alert_id,
            item.case_id,
            item.case_authority_sha256,
            item.policy_request_id,
            item.priority.value,
            item.idempotency_key,
            item.manifest_id,
        )
        if indexed != expected:
            raise RepositoryIntegrityError("outbox indexes differ from canonical content")
        return item

    def _require_outbox_close_authority(
        self,
        connection: sqlite3.Connection,
        outbox_row: sqlite3.Row,
        item: AlertOutboxItem,
    ) -> None:
        alert_row = connection.execute(
            """
            SELECT * FROM alerts WHERE run_id = ? AND authority_id = ?
            """,
            (item.run_id, _row_str(outbox_row, "alert_authority_id")),
        ).fetchone()
        if alert_row is None:
            raise RepositoryIntegrityError("outbox lost its alert authority")
        authority = self._alert_authority_from_row(alert_row)
        if authority.outbox_item != item:
            raise RepositoryIntegrityError("outbox differs from alert authority")
        closing = self._load_case_version_at(
            connection,
            run_id=item.run_id,
            case_id=item.case_id,
            revision=_row_int(alert_row, "closing_case_revision"),
        )
        if (
            closing.snapshot.case.status != CaseStatus.CLOSED
            or item.alert not in closing.snapshot.case.alerts
        ):
            raise RepositoryIntegrityError(
                "outbox alert is absent from the atomic CLOSED Case version"
            )
        precedent_rows = connection.execute(
            """
            SELECT * FROM precedents
            WHERE run_id = ? AND source = ? AND source_case_id = ? AND revision = 1
            """,
            (item.run_id, PrecedentSource.AUTOMATIC.value, item.case_id),
        ).fetchall()
        if len(precedent_rows) != 1:
            raise RepositoryIntegrityError("outbox Case lacks its atomic automatic precedent")
        automatic = self._m5_authority_from_row(connection, precedent_rows[0])
        if (
            automatic.precedent.source != PrecedentSource.AUTOMATIC
            or automatic.precedent.source_case_id != item.case_id
            or automatic.revision != 1
        ):
            raise RepositoryIntegrityError("outbox automatic precedent authority is invalid")

    @staticmethod
    def _dispatch_attempt_from_row(row: sqlite3.Row) -> AlertDispatchAttempt:
        attempt = _load_document(
            row,
            json_key="attempt_json",
            sha256_key="document_sha256",
            model_type=AlertDispatchAttempt,
        )
        indexed = (
            _row_str(row, "attempt_id"),
            _row_str(row, "outbox_id"),
            _row_str(row, "alert_id"),
            _row_str(row, "case_id"),
            _row_int(row, "attempt_number"),
            _row_int(row, "fence"),
            _row_str(row, "lease_owner_sha256"),
            _row_str(row, "started_at"),
            _row_str(row, "lease_expires_at"),
            _row_str(row, "channel_capability_id"),
            _row_str(row, "idempotency_key"),
        )
        expected = (
            attempt.attempt_id,
            attempt.outbox_id,
            attempt.alert_id,
            attempt.case_id,
            attempt.attempt_number,
            attempt.fence,
            attempt.lease_owner_sha256,
            _canonical_utc_timestamp(attempt.started_at, "dispatch started_at"),
            _canonical_utc_timestamp(
                attempt.lease_expires_at,
                "dispatch lease_expires_at",
            ),
            attempt.channel_capability.capability_id,
            attempt.idempotency_key,
        )
        if indexed != expected:
            raise RepositoryIntegrityError("dispatch attempt indexes differ from canonical content")
        return attempt

    @staticmethod
    def _dispatch_receipt_from_row(row: sqlite3.Row) -> AlertDispatchReceipt:
        receipt = _load_document(
            row,
            json_key="receipt_json",
            sha256_key="document_sha256",
            model_type=AlertDispatchReceipt,
        )
        indexed = (
            _row_str(row, "receipt_id"),
            _row_str(row, "attempt_id"),
            _row_str(row, "outbox_id"),
            _row_str(row, "alert_id"),
            _row_str(row, "case_id"),
            _row_int(row, "attempt_number"),
            _row_int(row, "fence"),
            _row_str(row, "lease_owner_sha256"),
            _row_str(row, "channel_capability_id"),
            _row_str(row, "idempotency_key"),
            _row_str(row, "disposition"),
            _row_str(row, "continuation"),
        )
        expected = (
            receipt.receipt_id,
            receipt.attempt_id,
            receipt.outbox_id,
            receipt.alert_id,
            receipt.case_id,
            receipt.attempt_number,
            receipt.fence,
            receipt.lease_owner_sha256,
            receipt.channel_capability.capability_id,
            receipt.idempotency_key,
            receipt.disposition.value,
            receipt.continuation.value,
        )
        if indexed != expected:
            raise RepositoryIntegrityError("dispatch receipt indexes differ from canonical content")
        return receipt

    def _load_successful_dispatch(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        outbox_id: str,
    ) -> AlertDispatchReceipt | None:
        rows = connection.execute(
            """
            SELECT * FROM alert_dispatch_receipts
            WHERE run_id = ? AND outbox_id = ? AND disposition = ?
            """,
            (run_id, outbox_id, AlertDispatchDisposition.SUCCEEDED.value),
        ).fetchall()
        if not rows:
            return None
        if len(rows) != 1:
            raise RepositoryIntegrityError("outbox has multiple successful dispatch authorities")
        return self._dispatch_receipt_from_row(rows[0])

    def _load_dispatch_attempts(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        outbox_id: str,
    ) -> tuple[AlertDispatchAttempt, ...]:
        rows = connection.execute(
            """
            SELECT * FROM alert_dispatch_attempts
            WHERE run_id = ? AND outbox_id = ? ORDER BY attempt_number
            """,
            (run_id, outbox_id),
        ).fetchall()
        attempts = tuple(self._dispatch_attempt_from_row(row) for row in rows)
        numbers = tuple(item.attempt_number for item in attempts)
        if numbers != tuple(range(1, len(numbers) + 1)):
            raise RepositoryIntegrityError("alert dispatch attempt sequence is not contiguous")
        if len({item.channel_capability.capability_id for item in attempts}) > 1:
            raise RepositoryIntegrityError("alert dispatch attempt sequence changed channel")
        for item in attempts[:-1]:
            receipt = self._load_dispatch_receipt(
                connection,
                run_id=run_id,
                attempt_id=item.attempt_id,
            )
            if receipt is None:
                raise RepositoryIntegrityError(
                    "alert dispatch successor exists before its predecessor was closed"
                )
            if receipt.continuation != AlertDispatchContinuation.RETRY_ALLOWED:
                raise RepositoryIntegrityError(
                    "alert dispatch successor follows a terminal predecessor"
                )
        return attempts

    def _load_dispatch_receipt(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        attempt_id: str,
    ) -> AlertDispatchReceipt | None:
        rows = connection.execute(
            """
            SELECT * FROM alert_dispatch_receipts
            WHERE run_id = ? AND attempt_id = ?
            """,
            (run_id, attempt_id),
        ).fetchall()
        if not rows:
            return None
        if len(rows) != 1:
            raise RepositoryIntegrityError("dispatch attempt has multiple outcome receipts")
        return self._dispatch_receipt_from_row(rows[0])

    @staticmethod
    def _expired_dispatch_receipt(attempt: AlertDispatchAttempt) -> AlertDispatchReceipt:
        retry_safe = (
            attempt.channel_capability.idempotency_guarantee.value == "EXACT_ALERT_ID"
            and attempt.channel_capability.provider_idempotency_key == "alert_id"
            and attempt.attempt_number < MAX_ALERT_DISPATCH_ATTEMPTS
        )
        return AlertDispatchReceipt(
            attempt_id=attempt.attempt_id,
            outbox_id=attempt.outbox_id,
            alert_id=attempt.alert_id,
            case_id=attempt.case_id,
            attempt_number=attempt.attempt_number,
            fence=attempt.fence,
            lease_owner_sha256=attempt.lease_owner_sha256,
            started_at=attempt.started_at,
            lease_expires_at=attempt.lease_expires_at,
            channel_capability=attempt.channel_capability,
            idempotency_key=attempt.idempotency_key,
            disposition=AlertDispatchDisposition.UNKNOWN_DELIVERY,
            continuation=(
                AlertDispatchContinuation.RETRY_ALLOWED
                if retry_safe
                else AlertDispatchContinuation.ATTENTION_REQUIRED
            ),
            failure_code=AlertDispatchFailureCode.LEASE_EXPIRED,
        )

    @staticmethod
    def _insert_dispatch_receipt(
        connection: sqlite3.Connection,
        run_id: str,
        receipt: AlertDispatchReceipt,
    ) -> None:
        receipt_json, document_sha256 = _document(receipt)
        connection.execute(
            """
            INSERT INTO alert_dispatch_receipts(
                run_id, receipt_id, attempt_id, outbox_id, alert_id,
                case_id, attempt_number, fence, lease_owner_sha256,
                channel_capability_id, idempotency_key, disposition,
                continuation, receipt_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                receipt.receipt_id,
                receipt.attempt_id,
                receipt.outbox_id,
                receipt.alert_id,
                receipt.case_id,
                receipt.attempt_number,
                receipt.fence,
                receipt.lease_owner_sha256,
                receipt.channel_capability.capability_id,
                receipt.idempotency_key,
                receipt.disposition.value,
                receipt.continuation.value,
                receipt_json,
                document_sha256,
            ),
        )


__all__ = [
    "MAX_AUTOMATIC_PRECEDENT_CLOCK_SKEW_SECONDS",
    "MAX_PENDING_ALERT_OUTBOX",
    "MAX_READY_ALERT_CASES",
    "SQLiteM5AlertRepository",
]
