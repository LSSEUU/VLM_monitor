"""Versioned backlog leasing, retry history, and failure authority."""

from __future__ import annotations

import sqlite3
from datetime import datetime

from labcourt.contracts.audit import AuditEntry
from labcourt.contracts.backlog import (
    BacklogCompletionReceipt,
    BacklogItem,
    BacklogLeaseIdentity,
    BacklogRetryContext,
    BacklogRetryFailure,
    BacklogRetrySuccess,
)
from labcourt.contracts.canonical import sha256_hex
from labcourt.contracts.cases import Case, TimelineEntry
from labcourt.contracts.enums import (
    ArtifactKind,
    AuditAction,
    BacklogReasonCode,
    BacklogStage,
    BacklogStatus,
    CaseStatus,
)
from labcourt.contracts.model_call_failures import (
    ModelCallFailureAuthority,
    ModelCallFailureClosureKind,
)
from labcourt.contracts.references import require_reference_token
from labcourt.contracts.screening import (
    ModelParseReceipt,
)
from labcourt.contracts.storage import ArtifactRef, ClosureReport
from labcourt.exceptions import (
    ConcurrentModification,
    ContractViolation,
    ManifestMismatch,
)
from labcourt.ports.evidence_repository import AuditHead, CaseSnapshot
from labcourt.ports.screening_repository import (
    M3BacklogRetryCommit,
    M3CaseCommit,
    ModelCallClaimStatus,
    ModelCallFailureIntent,
)

from .sqlite_m3_repository_host import SQLiteM3RepositoryHost
from .sqlite_m3_repository_support import (
    _load_document,
    _owner_token_sha256,
    _request_matches_retry_generation,
    _require_sha256,
    _validated_copy,
    _validated_request,
)
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


class SQLiteM3BacklogRepository(SQLiteM3RepositoryHost):
    """Versioned backlog leasing, retry history, and failure authority."""

    def enqueue(self, run_id: str, item: BacklogItem) -> BacklogItem:
        require_reference_token(run_id, "repository run_id")
        del item
        raise ContractViolation(
            "M3 backlog creation requires commit_backlog with Case and audit guards"
        )

    def commit_backlog(
        self,
        run_id: str,
        expected_revision: int,
        expected_audit_head: AuditHead,
        current_pack_closure: ClosureReport,
        item: BacklogItem,
        response_ids: tuple[str, ...] = (),
        model_call_failure: ModelCallFailureIntent | None = None,
    ) -> M3CaseCommit:
        """Atomically enqueue failed M3 work and bind the Case to BACKLOGGED.

        ``item.stage_input_sha256`` must equal ``m3_root_document_sha256`` for
        the referenced persisted root, not a pack construction/closure hash.
        """

        require_reference_token(run_id, "repository run_id")
        self._require_expected_revision(expected_revision)
        validated = _validated_copy(item, BacklogItem)
        if not isinstance(response_ids, tuple):
            raise TypeError("backlog response_ids must be a tuple")
        if len(set(response_ids)) != len(response_ids):
            raise ContractViolation("backlog response_ids must not contain duplicates")
        for response_id in response_ids:
            _require_sha256(response_id, "backlog response_id")
        if validated.run_id != run_id:
            raise ContractViolation("backlog item belongs to another run")
        if validated.status != BacklogStatus.PENDING or validated.attempt_count != 0:
            raise ContractViolation("new backlog work must start PENDING with zero attempts")
        item_json, item_sha256 = _document(validated)
        with self._immediate() as connection:
            snapshot = self._load_case(connection, run_id, validated.case_id)
            existing = self._load_backlog_optional(connection, run_id, validated.item_id)
            if existing is not None:
                self._require_same_backlog_identity(existing, validated)
                already_recorded = any(
                    entry.stage == "BACKLOG" and entry.object_ref == validated.item_id
                    for entry in snapshot.case.timeline
                )
                if already_recorded:
                    self._reverify_backlog_responses(
                        connection,
                        run_id=run_id,
                        response_ids=response_ids,
                        reason_code=validated.reason_code,
                    )
                    if validated.reason_code == BacklogReasonCode.MODEL_OUTPUT_INVALID:
                        self._strict_failure_history(
                            connection,
                            item=validated,
                            response_ids=response_ids,
                            expected_context=None,
                        )
                    if self._new_backlog_usage_response_ids(
                        connection,
                        snapshot=snapshot,
                        response_ids=response_ids,
                        backlog_item_id=validated.item_id,
                    ):
                        raise ConcurrentModification(
                            "backlog replay includes an unaccounted response"
                        )
                    if model_call_failure is not None:
                        self._require_model_call_failure_replay(
                            connection,
                            intent=model_call_failure,
                            item=existing,
                            closure_kind=ModelCallFailureClosureKind.INITIAL_BACKLOG,
                            receipt=None,
                        )
                    return M3CaseCommit(case=snapshot, created=False)

            if not snapshot.case.evidence_packs:
                raise ConcurrentModification("M3 backlog transition requires a current pack")
            if snapshot.case.status not in {
                CaseStatus.EVIDENCE_READY,
                CaseStatus.SCREENED,
            }:
                raise ConcurrentModification(
                    "M3 backlog requires an EVIDENCE_READY or SCREENED Case"
                )
            current_pack = snapshot.case.evidence_packs[-1]
            self._require_commit_guards(
                connection,
                snapshot=snapshot,
                expected_revision=expected_revision,
                expected_audit_head=expected_audit_head,
                current_pack_closure=current_pack_closure,
                pack_id=current_pack.pack_id,
                pack_version=current_pack.version,
                require_passed_closure=(
                    validated.reason_code != BacklogReasonCode.CURRENT_PACK_CHANGED
                ),
            )
            self._reverify_backlog_responses(
                connection,
                run_id=run_id,
                response_ids=response_ids,
                reason_code=validated.reason_code,
            )
            if validated.reason_code == BacklogReasonCode.MODEL_OUTPUT_INVALID:
                self._strict_failure_history(
                    connection,
                    item=validated,
                    response_ids=response_ids,
                    expected_context=None,
                )
            usage_response_ids = self._new_backlog_usage_response_ids(
                connection,
                snapshot=snapshot,
                response_ids=response_ids,
                backlog_item_id=validated.item_id,
            )
            self._enqueue_in_transaction(
                connection,
                validated,
                item_json=item_json,
                item_sha256=item_sha256,
            )
            usage_delta = self._consume_model_call_usage(
                connection,
                run_id=run_id,
                case_id=validated.case_id,
                response_ids=usage_response_ids,
                case_revision=snapshot.revision + 1,
                consumer_kind=ArtifactKind.BACKLOG_ITEM,
                consumer_id=validated.item_id,
            )
            new_case = self._case_with_updates(
                snapshot.case,
                status=CaseStatus.BACKLOGGED,
                current_backlog_item_id=validated.item_id,
                usage=self._add_usage(snapshot.case.usage, usage_delta),
                timeline_entry=TimelineEntry(
                    sequence=len(snapshot.case.timeline),
                    action=AuditAction.CASE_STATE_CHANGED.value,
                    stage="BACKLOG",
                    object_ref=validated.item_id,
                    details={
                        "reason_code": validated.reason_code.value,
                        "stage": validated.stage.value,
                    },
                ),
            )
            head = self._validated_head(connection, run_id)
            self._require_expected_head(head, expected_audit_head)
            committed = self._commit_case_version(
                connection,
                previous=snapshot,
                new_case=new_case,
                expected_head=head,
                object_ref=ArtifactRef(
                    kind=ArtifactKind.BACKLOG_ITEM,
                    artifact_id=validated.item_id,
                ),
            )
            if model_call_failure is not None:
                audit = self._load_audit_entry(
                    connection,
                    run_id,
                    expected_audit_head.sequence + 1,
                )
                self._insert_model_call_failure_authority(
                    connection,
                    intent=model_call_failure,
                    item=validated,
                    backlog_version=1,
                    closure_kind=ModelCallFailureClosureKind.INITIAL_BACKLOG,
                    committed=committed,
                    audit=audit,
                    receipt=None,
                )
            return M3CaseCommit(case=committed, created=True)

    def lease_next(
        self,
        run_id: str,
        stage: BacklogStage,
        lease_owner_sha256: str,
        lease_expires_at: datetime,
    ) -> BacklogItem | None:
        require_reference_token(run_id, "repository run_id")
        if not isinstance(stage, BacklogStage):
            raise TypeError("backlog lease stage must be a BacklogStage")
        _require_sha256(lease_owner_sha256, "lease_owner_sha256")
        expiry = self._canonical_timestamp(lease_expires_at, "lease_expires_at")
        with self._immediate() as connection:
            row = connection.execute(
                """
                SELECT biv.*
                FROM backlog_heads AS bh
                JOIN backlog_item_versions AS biv
                  ON biv.run_id = bh.run_id
                 AND biv.item_id = bh.item_id
                 AND biv.version = bh.current_version
                JOIN backlog_items AS bi
                  ON bi.run_id = bh.run_id
                 AND bi.item_id = bh.item_id
                JOIN cases AS c
                  ON c.run_id = bi.run_id
                 AND c.case_id = bi.case_id
                 AND c.status = 'BACKLOGGED'
                WHERE bh.run_id = ? AND bi.stage = ? AND biv.status = 'PENDING'
                ORDER BY bh.item_id
                LIMIT 1
                """,
                (run_id, stage.value),
            ).fetchone()
            if row is None:
                return None
            current = self._backlog_from_row(connection, row)
            bound_case = self._load_case(connection, run_id, current.case_id)
            if bound_case.case.current_backlog_item_id != current.item_id:
                raise RepositoryIntegrityError(
                    "pending backlog item is not the current Case retry boundary"
                )
            next_attempt = current.attempt_count + 1
            if next_attempt > current.max_attempts:
                raise RepositoryIntegrityError("pending backlog head exceeds its retry budget")
            lease_id = sha256_hex(
                [
                    "backlog-lease",
                    1,
                    run_id,
                    current.item_id,
                    next_attempt,
                    lease_owner_sha256,
                    expiry,
                ]
            )
            leased = BacklogItem.model_validate(
                {
                    **current.model_dump(mode="json", exclude_computed_fields=True),
                    "attempt_count": next_attempt,
                    "status": BacklogStatus.LEASED.value,
                    "lease_id": lease_id,
                    "lease_owner_sha256": lease_owner_sha256,
                    "lease_expires_at": expiry,
                }
            )
            self._advance_backlog(connection, current, leased)
            return leased

    def complete(
        self,
        run_id: str,
        item_id: str,
        expected_lease_id: str,
    ) -> BacklogItem:
        """Replay only an already-authoritative atomic success completion."""

        require_reference_token(run_id, "repository run_id")
        _require_sha256(item_id, "item_id")
        _require_sha256(expected_lease_id, "expected_lease_id")
        with self._read() as connection:
            rows = connection.execute(
                """
                SELECT * FROM backlog_completion_receipts
                WHERE run_id = ? AND item_id = ? AND lease_id = ?
                """,
                (run_id, item_id, expected_lease_id),
            ).fetchall()
            if len(rows) != 1:
                raise ContractViolation(
                    "backlog completion requires one exact atomic success receipt"
                )
            receipt = self._backlog_completion_receipt_from_row(connection, rows[0])
            if (
                not isinstance(receipt.outcome, BacklogRetrySuccess)
                or receipt.backlog_status != BacklogStatus.COMPLETED
            ):
                raise ContractViolation(
                    "standalone backlog completion cannot replace an atomic retry outcome"
                )
            self._reverify_backlog_responses(
                connection,
                run_id=run_id,
                response_ids=tuple(ref.artifact_id for ref in receipt.outcome.response_refs),
                reason_code=BacklogReasonCode.PROVIDER_UNAVAILABLE,
            )
            item = self._load_backlog_version(
                connection,
                run_id,
                item_id,
                _row_int(rows[0], "backlog_version"),
            )
            if item.status != BacklogStatus.COMPLETED:
                raise RepositoryIntegrityError(
                    "atomic success receipt does not bind a completed backlog version"
                )
            return item

    def release(
        self,
        run_id: str,
        item_id: str,
        expected_lease_id: str,
    ) -> BacklogItem:
        require_reference_token(run_id, "repository run_id")
        _require_sha256(item_id, "item_id")
        _require_sha256(expected_lease_id, "expected_lease_id")
        raise ContractViolation(
            "backlog release requires commit_backlog_retry_failure with Case and audit guards"
        )

    def reclaim_expired(
        self,
        run_id: str,
        not_after: datetime,
        limit: int,
    ) -> tuple[BacklogItem, ...]:
        require_reference_token(run_id, "repository run_id")
        cutoff_text = self._canonical_timestamp(not_after, "not_after")
        cutoff = _parse_utc_timestamp(cutoff_text, "not_after")
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 10_000:
            raise ValueError("backlog reclaim limit must be an integer in [1, 10000]")
        with self._immediate() as connection:
            rows = connection.execute(
                """
                SELECT biv.*
                FROM backlog_heads AS bh
                JOIN backlog_item_versions AS biv
                  ON biv.run_id = bh.run_id
                 AND biv.item_id = bh.item_id
                 AND biv.version = bh.current_version
                JOIN backlog_items AS bi
                  ON bi.run_id = bh.run_id
                 AND bi.item_id = bh.item_id
                JOIN cases AS c
                  ON c.run_id = bi.run_id
                 AND c.case_id = bi.case_id
                 AND c.status = 'BACKLOGGED'
                WHERE bh.run_id = ?
                  AND bi.stage = 'SCREENING'
                  AND biv.status = 'LEASED'
                  AND biv.lease_expires_at <= ?
                ORDER BY biv.lease_expires_at, biv.item_id
                LIMIT ?
                """,
                (run_id, cutoff_text, limit),
            ).fetchall()
            reclaimed: list[BacklogItem] = []
            for row in rows:
                current = self._backlog_from_row(connection, row)
                reclaimed.append(
                    self._commit_expired_backlog_lease(
                        connection,
                        current=current,
                        cutoff=cutoff,
                    ).item
                )
            return tuple(reclaimed)

    def load_backlog_item(self, run_id: str, item_id: str) -> BacklogItem:
        require_reference_token(run_id, "repository run_id")
        _require_sha256(item_id, "item_id")
        with self._read() as connection:
            item = self._load_backlog_optional(connection, run_id, item_id)
            if item is None:
                raise ContractViolation("unknown backlog item")
            return item

    def _commit_expired_backlog_lease(
        self,
        connection: sqlite3.Connection,
        *,
        current: BacklogItem,
        cutoff: datetime,
    ) -> M3BacklogRetryCommit:
        if current.stage != BacklogStage.SCREENING:
            raise ContractViolation("M3 backlog reclaim accepts only SCREENING work")
        if (
            current.status != BacklogStatus.LEASED
            or current.lease_id is None
            or current.lease_expires_at is None
            or current.lease_expires_at > cutoff
        ):
            raise ConcurrentModification("backlog lease is not expired under the reclaim cutoff")
        snapshot = self._load_case(connection, current.run_id, current.case_id)
        if (
            snapshot.case.status != CaseStatus.BACKLOGGED
            or snapshot.case.current_backlog_item_id != current.item_id
        ):
            raise RepositoryIntegrityError(
                "expired backlog item is not the current Case retry boundary"
            )
        if snapshot.case.manifest_id != current.manifest_id:
            raise RepositoryIntegrityError("expired backlog Case uses another manifest")
        next_status = (
            BacklogStatus.EXHAUSTED
            if current.attempt_count == current.max_attempts
            else BacklogStatus.PENDING
        )
        lease = BacklogLeaseIdentity(
            run_id=current.run_id,
            item_id=current.item_id,
            lease_id=current.lease_id,
            attempt_count=current.attempt_count,
            retry_generation=current.retry_generation,
        )
        failure = BacklogRetryFailure(
            lease=lease,
            reason_code=BacklogReasonCode.WORKER_LEASE_EXPIRED,
            next_status=next_status,
            manifest_id=current.manifest_id,
        )
        updated = BacklogItem.model_validate(
            {
                **current.model_dump(mode="json", exclude_computed_fields=True),
                "status": next_status.value,
                "lease_id": None,
                "lease_owner_sha256": None,
                "lease_expires_at": None,
            }
        )
        new_case = self._case_with_updates(
            snapshot.case,
            status=failure.completion_case_status,
            current_backlog_item_id=(
                current.item_id if next_status == BacklogStatus.PENDING else None
            ),
            timeline_entry=TimelineEntry(
                sequence=len(snapshot.case.timeline),
                action=AuditAction.CASE_STATE_CHANGED.value,
                stage="BACKLOG",
                object_ref=current.item_id,
                details={
                    "outcome": "FAILURE",
                    "reason_code": BacklogReasonCode.WORKER_LEASE_EXPIRED.value,
                    "status": next_status.value,
                    "retry_generation": current.retry_generation,
                },
            ),
        )
        completion_ref = ArtifactRef(
            kind=ArtifactKind.BACKLOG_ITEM,
            artifact_id=current.item_id,
        )
        head = self._validated_head(connection, current.run_id)
        audit_sequence = head.sequence + 1
        backlog_version = self._advance_backlog(connection, current, updated)
        committed = self._commit_case_version(
            connection,
            previous=snapshot,
            new_case=new_case,
            expected_head=head,
            object_ref=completion_ref,
        )
        audit = self._load_audit_entry(connection, current.run_id, audit_sequence)
        receipt = BacklogCompletionReceipt(
            outcome=failure,
            backlog_status=next_status,
            completion_ref=completion_ref,
            completion_case_status=failure.completion_case_status,
            completion_case_revision=committed.revision,
            completion_audit_sequence=audit.sequence,
            completion_audit_entry_hash=audit.entry_hash,
            manifest_id=current.manifest_id,
        )
        self._insert_backlog_completion_receipt(
            connection,
            item=updated,
            backlog_version=backlog_version,
            receipt=receipt,
        )
        return M3BacklogRetryCommit(
            case=committed,
            item=updated,
            receipt=receipt,
            created=True,
        )

    def _enqueue_in_transaction(
        self,
        connection: sqlite3.Connection,
        item: BacklogItem,
        *,
        item_json: str,
        item_sha256: str,
    ) -> tuple[BacklogItem, bool]:
        existing = self._load_backlog_optional(connection, item.run_id, item.item_id)
        if existing is not None:
            self._require_same_backlog_identity(existing, item)
            return existing, False
        self._require_case_manifest(
            connection,
            run_id=item.run_id,
            case_id=item.case_id,
            manifest_id=item.manifest_id,
        )
        self._require_stage_input(
            connection,
            item.stage_input_ref,
            run_id=item.run_id,
            case_id=item.case_id,
            expected_sha256=item.stage_input_sha256,
        )
        connection.execute(
            """
            INSERT INTO backlog_items(
                run_id, item_id, case_id, stage, role, reason_code,
                stage_input_kind, stage_input_id, stage_input_sha256,
                max_attempts, manifest_id,
                initial_json, initial_document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                item.run_id,
                item.item_id,
                item.case_id,
                item.stage.value,
                item.role.value if item.role is not None else None,
                item.reason_code.value,
                item.stage_input_ref.kind.value,
                item.stage_input_ref.artifact_id,
                item.stage_input_sha256,
                item.max_attempts,
                item.manifest_id,
                item_json,
                item_sha256,
            ),
        )
        self._insert_backlog_version(connection, item, version=1)
        connection.execute(
            """
            INSERT INTO backlog_heads(run_id, item_id, current_version)
            VALUES (?, ?, 1)
            """,
            (item.run_id, item.item_id),
        )
        return item, True

    def _load_backlog_optional(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        item_id: str,
    ) -> BacklogItem | None:
        row = connection.execute(
            """
            SELECT biv.*
            FROM backlog_heads AS bh
            JOIN backlog_item_versions AS biv
              ON biv.run_id = bh.run_id
             AND biv.item_id = bh.item_id
             AND biv.version = bh.current_version
            WHERE bh.run_id = ? AND bh.item_id = ?
            """,
            (run_id, item_id),
        ).fetchone()
        if row is None:
            identity = connection.execute(
                """
                SELECT 1 FROM backlog_items WHERE run_id = ? AND item_id = ?
                """,
                (run_id, item_id),
            ).fetchone()
            if identity is not None:
                raise RepositoryIntegrityError("backlog identity has no current head")
            return None
        return self._backlog_from_row(connection, row)

    def _backlog_from_row(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> BacklogItem:
        item = _load_document(
            row,
            json_key="item_json",
            sha256_key="document_sha256",
            model_type=BacklogItem,
        )
        version = _row_int(row, "version")
        indexed = (
            _row_str(row, "run_id"),
            _row_str(row, "item_id"),
            _row_str(row, "status"),
            _row_int(row, "attempt_count"),
            _row_int(row, "retry_generation"),
            _row_optional_str(row, "lease_id"),
            _row_optional_str(row, "lease_owner_sha256"),
            _row_optional_str(row, "lease_expires_at"),
        )
        expected = (
            item.run_id,
            item.item_id,
            item.status.value,
            item.attempt_count,
            item.retry_generation,
            item.lease_id,
            item.lease_owner_sha256,
            self._canonical_timestamp(item.lease_expires_at, "stored lease expiry")
            if item.lease_expires_at is not None
            else None,
        )
        if indexed != expected:
            raise RepositoryIntegrityError("backlog version indexes differ from canonical content")
        identity_row = connection.execute(
            """
            SELECT *, (
                SELECT MAX(v.version) FROM backlog_item_versions AS v
                WHERE v.run_id = backlog_items.run_id
                  AND v.item_id = backlog_items.item_id
            ) AS max_version
            FROM backlog_items WHERE run_id = ? AND item_id = ?
            """,
            (item.run_id, item.item_id),
        ).fetchone()
        if identity_row is None or version != _row_int(identity_row, "max_version"):
            raise RepositoryIntegrityError(
                "backlog head does not select its latest immutable version"
            )
        initial = _load_document(
            identity_row,
            json_key="initial_json",
            sha256_key="initial_document_sha256",
            model_type=BacklogItem,
        )
        self._require_same_backlog_identity(initial, item)
        identity_index = (
            _row_str(identity_row, "run_id"),
            _row_str(identity_row, "item_id"),
            _row_str(identity_row, "case_id"),
            _row_str(identity_row, "stage"),
            _row_optional_str(identity_row, "role"),
            _row_str(identity_row, "reason_code"),
            _row_str(identity_row, "stage_input_kind"),
            _row_str(identity_row, "stage_input_id"),
            _row_str(identity_row, "stage_input_sha256"),
            _row_int(identity_row, "max_attempts"),
            _row_str(identity_row, "manifest_id"),
        )
        expected_identity = (
            item.run_id,
            item.item_id,
            item.case_id,
            item.stage.value,
            item.role.value if item.role is not None else None,
            item.reason_code.value,
            item.stage_input_ref.kind.value,
            item.stage_input_ref.artifact_id,
            item.stage_input_sha256,
            item.max_attempts,
            item.manifest_id,
        )
        if identity_index != expected_identity:
            raise RepositoryIntegrityError("backlog identity indexes differ from canonical content")
        return item

    @staticmethod
    def _require_same_backlog_identity(left: BacklogItem, right: BacklogItem) -> None:
        if (
            left.item_id != right.item_id
            or left.run_id != right.run_id
            or left.case_id != right.case_id
            or left.stage != right.stage
            or left.role != right.role
            or left.reason_code != right.reason_code
            or left.stage_input_ref != right.stage_input_ref
            or left.stage_input_sha256 != right.stage_input_sha256
            or left.max_attempts != right.max_attempts
            or left.manifest_id != right.manifest_id
        ):
            raise RepositoryIntegrityError(
                "backlog item_id already binds different immutable input"
            )

    def _insert_backlog_version(
        self,
        connection: sqlite3.Connection,
        item: BacklogItem,
        *,
        version: int,
    ) -> None:
        item_json, item_sha256 = _document(item)
        connection.execute(
            """
            INSERT INTO backlog_item_versions(
                run_id, item_id, version, status, attempt_count,
                retry_generation,
                lease_id, lease_owner_sha256, lease_expires_at,
                item_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                item.run_id,
                item.item_id,
                version,
                item.status.value,
                item.attempt_count,
                item.retry_generation,
                item.lease_id,
                item.lease_owner_sha256,
                self._canonical_timestamp(item.lease_expires_at, "lease_expires_at")
                if item.lease_expires_at is not None
                else None,
                item_json,
                item_sha256,
            ),
        )

    def _advance_backlog(
        self,
        connection: sqlite3.Connection,
        current: BacklogItem,
        updated: BacklogItem,
    ) -> int:
        self._require_same_backlog_identity(current, updated)
        row = connection.execute(
            """
            SELECT current_version FROM backlog_heads
            WHERE run_id = ? AND item_id = ?
            """,
            (current.run_id, current.item_id),
        ).fetchone()
        if row is None:
            raise RepositoryIntegrityError("backlog item has no head")
        version = _row_int(row, "current_version")
        self._insert_backlog_version(connection, updated, version=version + 1)
        cursor = connection.execute(
            """
            UPDATE backlog_heads SET current_version = ?
            WHERE run_id = ? AND item_id = ? AND current_version = ?
            """,
            (version + 1, current.run_id, current.item_id, version),
        )
        if cursor.rowcount != 1:
            raise ConcurrentModification("backlog head changed during lease transition")
        return version + 1

    def _load_backlog_version(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        item_id: str,
        version: int,
    ) -> BacklogItem:
        row = connection.execute(
            """
            SELECT * FROM backlog_item_versions
            WHERE run_id = ? AND item_id = ? AND version = ?
            """,
            (run_id, item_id, version),
        ).fetchone()
        if row is None:
            raise RepositoryIntegrityError("backlog receipt version authority is missing")
        item = _load_document(
            row,
            json_key="item_json",
            sha256_key="document_sha256",
            model_type=BacklogItem,
        )
        indexed = (
            _row_str(row, "run_id"),
            _row_str(row, "item_id"),
            _row_str(row, "status"),
            _row_int(row, "attempt_count"),
            _row_int(row, "retry_generation"),
            _row_optional_str(row, "lease_id"),
            _row_optional_str(row, "lease_owner_sha256"),
            _row_optional_str(row, "lease_expires_at"),
        )
        expected = (
            item.run_id,
            item.item_id,
            item.status.value,
            item.attempt_count,
            item.retry_generation,
            item.lease_id,
            item.lease_owner_sha256,
            (
                self._canonical_timestamp(item.lease_expires_at, "stored lease expiry")
                if item.lease_expires_at is not None
                else None
            ),
        )
        if indexed != expected:
            raise RepositoryIntegrityError(
                "backlog receipt version indexes differ from canonical content"
            )
        identity_row = connection.execute(
            "SELECT * FROM backlog_items WHERE run_id = ? AND item_id = ?",
            (run_id, item_id),
        ).fetchone()
        if identity_row is None:
            raise RepositoryIntegrityError("backlog receipt identity authority is missing")
        initial = _load_document(
            identity_row,
            json_key="initial_json",
            sha256_key="initial_document_sha256",
            model_type=BacklogItem,
        )
        self._require_same_backlog_identity(initial, item)
        identity_index = (
            _row_str(identity_row, "run_id"),
            _row_str(identity_row, "item_id"),
            _row_str(identity_row, "case_id"),
            _row_str(identity_row, "stage"),
            _row_optional_str(identity_row, "role"),
            _row_str(identity_row, "reason_code"),
            _row_str(identity_row, "stage_input_kind"),
            _row_str(identity_row, "stage_input_id"),
            _row_str(identity_row, "stage_input_sha256"),
            _row_int(identity_row, "max_attempts"),
            _row_str(identity_row, "manifest_id"),
        )
        expected_identity = (
            item.run_id,
            item.item_id,
            item.case_id,
            item.stage.value,
            item.role.value if item.role is not None else None,
            item.reason_code.value,
            item.stage_input_ref.kind.value,
            item.stage_input_ref.artifact_id,
            item.stage_input_sha256,
            item.max_attempts,
            item.manifest_id,
        )
        if identity_index != expected_identity:
            raise RepositoryIntegrityError(
                "backlog receipt identity indexes differ from canonical content"
            )
        return item

    def _load_case_version(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        case_id: str,
        revision: int,
    ) -> CaseSnapshot:
        row = connection.execute(
            """
            SELECT * FROM case_versions
            WHERE run_id = ? AND case_id = ? AND revision = ?
            """,
            (run_id, case_id, revision),
        ).fetchone()
        if row is None:
            raise RepositoryIntegrityError("backlog receipt Case version authority is missing")
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
                "backlog receipt Case indexes differ from canonical content"
            )
        self._verify_case_roots(connection, case, allow_future_roots=True)
        return CaseSnapshot(case=case, revision=revision)

    def _backlog_completion_receipt_from_row(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> BacklogCompletionReceipt:
        receipt = _load_document(
            row,
            json_key="receipt_json",
            sha256_key="document_sha256",
            model_type=BacklogCompletionReceipt,
        )
        outcome = receipt.outcome
        item = self._load_backlog_version(
            connection,
            _row_str(row, "run_id"),
            _row_str(row, "item_id"),
            _row_int(row, "backlog_version"),
        )
        indexed = (
            _row_str(row, "run_id"),
            _row_str(row, "receipt_id"),
            _row_str(row, "item_id"),
            _row_str(row, "case_id"),
            _row_str(row, "outcome_kind"),
            _row_str(row, "outcome_id"),
            _row_str(row, "lease_identity_sha256"),
            _row_str(row, "lease_id"),
            _row_int(row, "attempt_count"),
            _row_int(row, "retry_generation"),
            _row_str(row, "backlog_status"),
            _row_str(row, "completion_kind"),
            _row_str(row, "completion_id"),
            _row_str(row, "completion_case_status"),
            _row_int(row, "completion_case_revision"),
            _row_int(row, "completion_audit_sequence"),
            _row_str(row, "completion_audit_entry_hash"),
            _row_str(row, "manifest_id"),
        )
        expected = (
            outcome.lease.run_id,
            receipt.receipt_id,
            outcome.lease.item_id,
            item.case_id,
            outcome.outcome_kind,
            outcome.outcome_id,
            outcome.lease.lease_identity_sha256,
            outcome.lease.lease_id,
            outcome.lease.attempt_count,
            outcome.lease.retry_generation,
            receipt.backlog_status.value,
            receipt.completion_ref.kind.value,
            receipt.completion_ref.artifact_id,
            receipt.completion_case_status.value,
            receipt.completion_case_revision,
            receipt.completion_audit_sequence,
            receipt.completion_audit_entry_hash,
            receipt.manifest_id,
        )
        if indexed != expected:
            raise RepositoryIntegrityError(
                "backlog completion receipt indexes differ from canonical content"
            )
        expected_item_generation = (
            outcome.next_retry_generation
            if isinstance(outcome, BacklogRetryFailure)
            else outcome.lease.retry_generation
        )
        if (
            item.run_id != outcome.lease.run_id
            or item.item_id != outcome.lease.item_id
            or item.attempt_count != outcome.lease.attempt_count
            or item.retry_generation != expected_item_generation
            or item.manifest_id != receipt.manifest_id
            or item.status != receipt.backlog_status
        ):
            raise RepositoryIntegrityError(
                "backlog completion receipt differs from its immutable item version"
            )
        case = self._load_case_version(
            connection,
            outcome.lease.run_id,
            item.case_id,
            receipt.completion_case_revision,
        )
        if (
            case.case.status != receipt.completion_case_status
            or case.case.manifest_id != receipt.manifest_id
        ):
            raise RepositoryIntegrityError(
                "backlog completion receipt differs from its immutable Case version"
            )
        audit_row = connection.execute(
            "SELECT * FROM audit_entries WHERE run_id = ? AND sequence = ?",
            (outcome.lease.run_id, receipt.completion_audit_sequence),
        ).fetchone()
        if audit_row is None:
            raise RepositoryIntegrityError("backlog completion receipt audit is missing")
        audit = _audit_entry_from_row(audit_row)
        case_document_sha256 = _document(case.case)[1]
        if (
            audit.entry_hash != receipt.completion_audit_entry_hash
            or audit.object_ref != receipt.completion_ref
            or audit.after_sha256 != case_document_sha256
            or _row_int(
                connection.execute(
                    """
                    SELECT audit_sequence FROM case_versions
                    WHERE run_id = ? AND case_id = ? AND revision = ?
                    """,
                    (
                        outcome.lease.run_id,
                        item.case_id,
                        receipt.completion_case_revision,
                    ),
                ).fetchone(),
                "audit_sequence",
            )
            != audit.sequence
        ):
            raise RepositoryIntegrityError(
                "backlog completion receipt differs from its audit authority"
            )
        if receipt.completion_ref.kind == ArtifactKind.SCREENING_RESULT:
            self._load_screening(
                connection,
                outcome.lease.run_id,
                receipt.completion_ref.artifact_id,
            )
        elif receipt.completion_ref.kind == ArtifactKind.PROCEDURAL_REVIEW:
            self._load_review(
                connection,
                outcome.lease.run_id,
                receipt.completion_ref.artifact_id,
            )
        return receipt

    def _insert_backlog_completion_receipt(
        self,
        connection: sqlite3.Connection,
        *,
        item: BacklogItem,
        backlog_version: int,
        receipt: BacklogCompletionReceipt,
    ) -> None:
        receipt_json, receipt_sha256 = _document(receipt)
        outcome = receipt.outcome
        connection.execute(
            """
            INSERT INTO backlog_completion_receipts(
                run_id, receipt_id, item_id, case_id,
                outcome_kind, outcome_id, lease_identity_sha256, lease_id,
                attempt_count, retry_generation, backlog_status, backlog_version,
                completion_kind, completion_id, completion_case_status,
                completion_case_revision, completion_audit_sequence,
                completion_audit_entry_hash, manifest_id,
                receipt_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                outcome.lease.run_id,
                receipt.receipt_id,
                outcome.lease.item_id,
                item.case_id,
                outcome.outcome_kind,
                outcome.outcome_id,
                outcome.lease.lease_identity_sha256,
                outcome.lease.lease_id,
                outcome.lease.attempt_count,
                outcome.lease.retry_generation,
                receipt.backlog_status.value,
                backlog_version,
                receipt.completion_ref.kind.value,
                receipt.completion_ref.artifact_id,
                receipt.completion_case_status.value,
                receipt.completion_case_revision,
                receipt.completion_audit_sequence,
                receipt.completion_audit_entry_hash,
                receipt.manifest_id,
                receipt_json,
                receipt_sha256,
            ),
        )

    def _insert_model_call_failure_authority(
        self,
        connection: sqlite3.Connection,
        *,
        intent: ModelCallFailureIntent,
        item: BacklogItem,
        backlog_version: int,
        closure_kind: ModelCallFailureClosureKind,
        committed: CaseSnapshot,
        audit: AuditEntry,
        receipt: BacklogCompletionReceipt | None,
    ) -> ModelCallFailureAuthority:
        if not isinstance(intent, ModelCallFailureIntent):
            raise TypeError("model_call_failure must be a ModelCallFailureIntent")
        request = _validated_request(intent.request)
        owner_sha256 = _owner_token_sha256(intent.owner_token)
        expiry_text = self._canonical_timestamp(
            intent.claim_lease_expires_at,
            "model call failure claim lease expiry",
        )
        rows = connection.execute(
            """
            SELECT * FROM model_call_claims
            WHERE run_id = ? AND request_id = ?
            """,
            (request.run_id, request.request_id),
        ).fetchall()
        if len(rows) != 1:
            raise ContractViolation("model call failure authority requires one exact active claim")
        claim_row = rows[0]
        claim = self._claim_from_row(claim_row, request)
        if (
            claim.status != ModelCallClaimStatus.WAITING
            or _row_str(claim_row, "owner_token_sha256") != owner_sha256
            or _row_str(claim_row, "lease_expires_at") != expiry_text
            or _row_int(claim_row, "takeover_count") != intent.claim_takeover_count
        ):
            raise ConcurrentModification(
                "model call failure owner no longer holds the exact active claim epoch"
            )
        if (
            item.run_id != request.run_id
            or item.case_id != request.case_id
            or item.manifest_id != request.manifest_id
            or item.reason_code != intent.backlog_reason_code
            or item.role != request.role
            or committed.case.run_id != request.run_id
            or committed.case.case_id != request.case_id
            or committed.case.manifest_id != request.manifest_id
            or audit.object_ref
            != ArtifactRef(kind=ArtifactKind.BACKLOG_ITEM, artifact_id=item.item_id)
            or audit.manifest_id != request.manifest_id
        ):
            raise ContractViolation(
                "model call failure intent conflicts with its aggregate closure"
            )
        context = request.backlog_retry_context
        if closure_kind == ModelCallFailureClosureKind.INITIAL_BACKLOG:
            if (
                context is not None
                or receipt is not None
                or backlog_version != 1
                or item.attempt_count != 0
                or item.retry_generation != 0
                or item.status != BacklogStatus.PENDING
            ):
                raise ContractViolation("initial model call failure closure is invalid")
        else:
            if (
                context is None
                or context.backlog_item_id != item.item_id
                or context.retry_generation != item.retry_generation
                or receipt is None
                or not isinstance(receipt.outcome, BacklogRetryFailure)
                or receipt.outcome.reason_code != intent.backlog_reason_code
                or receipt.outcome.lease.item_id != item.item_id
                or receipt.outcome.lease.retry_generation != item.retry_generation
                or receipt.outcome.lease.attempt_count != item.attempt_count
                or item.status not in {BacklogStatus.PENDING, BacklogStatus.EXHAUSTED}
            ):
                raise ContractViolation("retry model call failure closure is invalid")
        authority = ModelCallFailureAuthority(
            run_id=request.run_id,
            request=request,
            claim_owner_sha256=owner_sha256,
            claim_lease_expires_at=intent.claim_lease_expires_at,
            claim_takeover_count=intent.claim_takeover_count,
            failure_code=intent.failure_code,
            delivery_certainty=intent.delivery_certainty,
            backlog_reason_code=intent.backlog_reason_code,
            backlog_item_id=item.item_id,
            backlog_version=backlog_version,
            backlog_status=item.status,
            backlog_attempt_count=item.attempt_count,
            retry_generation=item.retry_generation,
            closure_kind=closure_kind,
            completion_receipt_id=receipt.receipt_id if receipt is not None else None,
            closure_case_revision=committed.revision,
            closure_audit_sequence=audit.sequence,
            closure_audit_entry_hash=audit.entry_hash,
            manifest_id=request.manifest_id,
            recorded_at=_parse_utc_timestamp(
                self._recorded_at(),
                "model call failure authority time",
            ),
        )
        authority_json, authority_sha256 = _document(authority)
        connection.execute(
            """
            INSERT INTO model_call_failure_authorities(
                run_id, authority_id, request_id, request_sha256,
                request_document_sha256, cache_key, case_id,
                evidence_pack_id, evidence_pack_version, purpose,
                model_manifest_id, claim_owner_sha256,
                claim_lease_expires_at, claim_takeover_count,
                failure_code, delivery_certainty, backlog_reason_code,
                backlog_item_id, backlog_version, backlog_status,
                backlog_attempt_count, retry_generation, closure_kind,
                completion_receipt_id, closure_case_revision,
                closure_audit_sequence, closure_audit_entry_hash,
                manifest_id, recorded_at, authority_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                      ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                authority.run_id,
                authority.authority_id,
                authority.request.request_id,
                authority.request.request_sha256,
                authority.request_document_sha256,
                authority.request.cache_key,
                authority.request.case_id,
                authority.request.evidence_pack_id,
                authority.request.evidence_pack_version,
                authority.request.purpose.value,
                authority.request.model_manifest_id,
                authority.claim_owner_sha256,
                self._canonical_timestamp(
                    authority.claim_lease_expires_at,
                    "model call failure authority claim expiry",
                ),
                authority.claim_takeover_count,
                authority.failure_code.value,
                authority.delivery_certainty.value,
                authority.backlog_reason_code.value,
                authority.backlog_item_id,
                authority.backlog_version,
                authority.backlog_status.value,
                authority.backlog_attempt_count,
                authority.retry_generation,
                authority.closure_kind.value,
                authority.completion_receipt_id,
                authority.closure_case_revision,
                authority.closure_audit_sequence,
                authority.closure_audit_entry_hash,
                authority.manifest_id,
                self._canonical_timestamp(
                    authority.recorded_at,
                    "model call failure authority time",
                ),
                authority_json,
                authority_sha256,
            ),
        )
        return authority

    def _model_call_failure_authority_from_row(
        self,
        row: sqlite3.Row,
    ) -> ModelCallFailureAuthority:
        authority = _load_document(
            row,
            json_key="authority_json",
            sha256_key="document_sha256",
            model_type=ModelCallFailureAuthority,
        )
        indexed = (
            _row_str(row, "run_id"),
            _row_str(row, "authority_id"),
            _row_str(row, "request_id"),
            _row_str(row, "request_sha256"),
            _row_str(row, "request_document_sha256"),
            _row_str(row, "cache_key"),
            _row_str(row, "case_id"),
            _row_str(row, "evidence_pack_id"),
            _row_int(row, "evidence_pack_version"),
            _row_str(row, "purpose"),
            _row_str(row, "model_manifest_id"),
            _row_str(row, "claim_owner_sha256"),
            _row_str(row, "claim_lease_expires_at"),
            _row_int(row, "claim_takeover_count"),
            _row_str(row, "failure_code"),
            _row_str(row, "delivery_certainty"),
            _row_str(row, "backlog_reason_code"),
            _row_str(row, "backlog_item_id"),
            _row_int(row, "backlog_version"),
            _row_str(row, "backlog_status"),
            _row_int(row, "backlog_attempt_count"),
            _row_int(row, "retry_generation"),
            _row_str(row, "closure_kind"),
            _row_optional_str(row, "completion_receipt_id"),
            _row_int(row, "closure_case_revision"),
            _row_int(row, "closure_audit_sequence"),
            _row_str(row, "closure_audit_entry_hash"),
            _row_str(row, "manifest_id"),
            _row_str(row, "recorded_at"),
        )
        expected = (
            authority.run_id,
            authority.authority_id,
            authority.request.request_id,
            authority.request.request_sha256,
            authority.request_document_sha256,
            authority.request.cache_key,
            authority.request.case_id,
            authority.request.evidence_pack_id,
            authority.request.evidence_pack_version,
            authority.request.purpose.value,
            authority.request.model_manifest_id,
            authority.claim_owner_sha256,
            self._canonical_timestamp(
                authority.claim_lease_expires_at,
                "stored model call failure claim expiry",
            ),
            authority.claim_takeover_count,
            authority.failure_code.value,
            authority.delivery_certainty.value,
            authority.backlog_reason_code.value,
            authority.backlog_item_id,
            authority.backlog_version,
            authority.backlog_status.value,
            authority.backlog_attempt_count,
            authority.retry_generation,
            authority.closure_kind.value,
            authority.completion_receipt_id,
            authority.closure_case_revision,
            authority.closure_audit_sequence,
            authority.closure_audit_entry_hash,
            authority.manifest_id,
            self._canonical_timestamp(
                authority.recorded_at,
                "stored model call failure authority time",
            ),
        )
        if indexed != expected:
            raise RepositoryIntegrityError(
                "model call failure authority indexes differ from canonical content"
            )
        return authority

    def _require_model_call_failure_replay(
        self,
        connection: sqlite3.Connection,
        *,
        intent: ModelCallFailureIntent,
        item: BacklogItem,
        closure_kind: ModelCallFailureClosureKind,
        receipt: BacklogCompletionReceipt | None,
    ) -> None:
        owner_sha256 = _owner_token_sha256(intent.owner_token)
        rows = connection.execute(
            """
            SELECT * FROM model_call_failure_authorities
            WHERE run_id = ? AND request_id = ? AND claim_takeover_count = ?
            """,
            (
                intent.request.run_id,
                intent.request.request_id,
                intent.claim_takeover_count,
            ),
        ).fetchall()
        if len(rows) != 1:
            raise RepositoryIntegrityError(
                "model call failure replay is missing its exact durable authority"
            )
        authority = self._model_call_failure_authority_from_row(rows[0])
        if (
            authority.request != intent.request
            or authority.claim_owner_sha256 != owner_sha256
            or authority.claim_lease_expires_at != intent.claim_lease_expires_at
            or authority.failure_code != intent.failure_code
            or authority.delivery_certainty != intent.delivery_certainty
            or authority.backlog_reason_code != intent.backlog_reason_code
            or authority.backlog_item_id != item.item_id
            or authority.closure_kind != closure_kind
            or authority.completion_receipt_id
            != (receipt.receipt_id if receipt is not None else None)
        ):
            raise ConcurrentModification(
                "model call failure replay differs from immutable authority"
            )

    def _load_backlog_retry_replay(
        self,
        connection: sqlite3.Connection,
        outcome: BacklogRetrySuccess | BacklogRetryFailure,
    ) -> M3BacklogRetryCommit | None:
        rows = connection.execute(
            """
            SELECT * FROM backlog_completion_receipts
            WHERE run_id = ?
              AND (outcome_id = ? OR (item_id = ? AND lease_identity_sha256 = ?))
            """,
            (
                outcome.lease.run_id,
                outcome.outcome_id,
                outcome.lease.item_id,
                outcome.lease.lease_identity_sha256,
            ),
        ).fetchall()
        if not rows:
            return None
        if len(rows) != 1:
            raise RepositoryIntegrityError(
                "backlog retry outcome identities select multiple completion receipts"
            )
        row = rows[0]
        receipt = self._backlog_completion_receipt_from_row(connection, row)
        if receipt.outcome != outcome:
            raise ConcurrentModification(
                "the exact backlog lease already committed a different outcome"
            )
        self._reverify_backlog_responses(
            connection,
            run_id=outcome.lease.run_id,
            response_ids=tuple(ref.artifact_id for ref in outcome.response_refs),
            reason_code=(
                outcome.reason_code
                if isinstance(outcome, BacklogRetryFailure)
                else BacklogReasonCode.PROVIDER_UNAVAILABLE
            ),
        )
        item = self._load_backlog_version(
            connection,
            outcome.lease.run_id,
            outcome.lease.item_id,
            _row_int(row, "backlog_version"),
        )
        case = self._load_case_version(
            connection,
            outcome.lease.run_id,
            item.case_id,
            receipt.completion_case_revision,
        )
        return M3BacklogRetryCommit(
            case=case,
            item=item,
            receipt=receipt,
            created=False,
        )

    def _require_active_backlog_lease(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        lease: BacklogLeaseIdentity,
        manifest_id: str,
    ) -> tuple[BacklogItem, CaseSnapshot]:
        if lease.run_id != run_id:
            raise ContractViolation("backlog lease belongs to another run")
        current = self._load_backlog_optional(connection, run_id, lease.item_id)
        if current is None:
            raise ContractViolation("unknown backlog item")
        if (
            current.status != BacklogStatus.LEASED
            or current.lease_id != lease.lease_id
            or current.attempt_count != lease.attempt_count
            or current.retry_generation != lease.retry_generation
        ):
            raise ConcurrentModification("backlog four-part lease identity does not match")
        if current.manifest_id != manifest_id:
            raise ManifestMismatch("backlog retry uses another run manifest")
        now = _parse_utc_timestamp(self._recorded_at(), "repository clock")
        if current.lease_expires_at is None or current.lease_expires_at <= now:
            raise ConcurrentModification("backlog lease expired before atomic completion")
        snapshot = self._load_case(connection, run_id, current.case_id)
        if (
            snapshot.case.status != CaseStatus.BACKLOGGED
            or snapshot.case.current_backlog_item_id != current.item_id
        ):
            raise ConcurrentModification(
                "backlog item is not the current BACKLOGGED Case retry boundary"
            )
        if snapshot.case.manifest_id != manifest_id:
            raise ManifestMismatch("backlog Case uses another run manifest")
        if current.stage.value != "SCREENING":
            raise ContractViolation("M3 atomic retry only accepts SCREENING backlog work")
        if not snapshot.case.evidence_packs:
            raise ConcurrentModification("backlog retry Case has no current evidence pack")
        current_pack = snapshot.case.evidence_packs[-1]
        if (
            current.stage_input_ref.kind != ArtifactKind.EVIDENCE_PACK
            or current.stage_input_ref.artifact_id != current_pack.pack_id
        ):
            raise ConcurrentModification("backlog stage input is not the current evidence pack")
        self._require_stage_input(
            connection,
            current.stage_input_ref,
            run_id=run_id,
            case_id=current.case_id,
            expected_sha256=current.stage_input_sha256,
        )
        return current, snapshot

    @staticmethod
    def _parse_history_response_refs(
        parse_history: tuple[ModelParseReceipt, ...],
    ) -> tuple[ArtifactRef, ...]:
        return tuple(
            sorted(
                (
                    ArtifactRef(
                        kind=ArtifactKind.MODEL_RESPONSE,
                        artifact_id=receipt.response_id,
                    )
                    for receipt in parse_history
                ),
                key=lambda ref: ref.sort_key,
            )
        )

    def _require_retry_parse_context(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        parse_history: tuple[ModelParseReceipt, ...],
        lease: BacklogLeaseIdentity,
    ) -> None:
        expected = BacklogRetryContext(
            backlog_item_id=lease.item_id,
            retry_generation=lease.retry_generation,
        )
        for receipt in parse_history:
            response = self._load_response(connection, run_id, receipt.response_id)
            request = self._request_for_response(connection, response)
            if not _request_matches_retry_generation(request, expected):
                raise ContractViolation(
                    "retry parse history does not bind the exact backlog generation"
                )

    def _load_audit_entry(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        sequence: int,
    ) -> AuditEntry:
        row = connection.execute(
            "SELECT * FROM audit_entries WHERE run_id = ? AND sequence = ?",
            (run_id, sequence),
        ).fetchone()
        if row is None:
            raise RepositoryIntegrityError("committed backlog retry audit entry is missing")
        return _audit_entry_from_row(row)

    def _backlog_transition_matches(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        item_id: str,
        expected_lease_id: str,
    ) -> bool:
        row = connection.execute(
            """
            SELECT previous.status, previous.lease_id
            FROM backlog_heads AS bh
            JOIN backlog_item_versions AS previous
              ON previous.run_id = bh.run_id
             AND previous.item_id = bh.item_id
             AND previous.version = bh.current_version - 1
            WHERE bh.run_id = ? AND bh.item_id = ?
            """,
            (run_id, item_id),
        ).fetchone()
        return row is not None and (
            _row_str(row, "status") == BacklogStatus.LEASED.value
            and _row_optional_str(row, "lease_id") == expected_lease_id
        )

    @staticmethod
    def _canonical_timestamp(value: datetime, name: str) -> str:
        try:
            return _canonical_utc_timestamp(value, name)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{name} must be a timezone-aware datetime") from exc

    def _require_stage_input(
        self,
        connection: sqlite3.Connection,
        ref: ArtifactRef,
        *,
        run_id: str,
        case_id: str,
        expected_sha256: str,
    ) -> None:
        table_map: dict[ArtifactKind, tuple[str, str, str, str | None]] = {
            ArtifactKind.CASE: (
                "case_versions",
                "case_id",
                "document_sha256",
                "revision = (SELECT current_revision FROM cases "
                "WHERE cases.run_id = case_versions.run_id "
                "AND cases.case_id = case_versions.case_id)",
            ),
            ArtifactKind.EVIDENCE_PACK: (
                "evidence_packs",
                "pack_id",
                "document_sha256",
                None,
            ),
            ArtifactKind.MODEL_RESPONSE: (
                "model_responses",
                "response_id",
                "document_sha256",
                None,
            ),
            ArtifactKind.SCREENING_RESULT: (
                "screening_results",
                "screening_id",
                "document_sha256",
                None,
            ),
            ArtifactKind.VERDICT: (
                "verdicts",
                "verdict_id",
                "document_sha256",
                None,
            ),
            ArtifactKind.PROCEDURAL_REVIEW: (
                "procedural_reviews",
                "review_id",
                "document_sha256",
                None,
            ),
        }
        if ref.kind == ArtifactKind.EVENT:
            row = connection.execute(
                """
                SELECT event_sha256 AS source_sha256 FROM cases
                WHERE run_id = ? AND case_id = ? AND event_id = ?
                """,
                (run_id, case_id, ref.artifact_id),
            ).fetchone()
        else:
            binding = table_map.get(ref.kind)
            if binding is None:
                raise ContractViolation("unsupported durable backlog stage input kind")
            table, id_column, sha_column, extra = binding
            query = (
                f"SELECT {sha_column} AS source_sha256 FROM {table} "
                f"WHERE run_id = ? AND case_id = ? AND {id_column} = ?"
            )
            if extra is not None:
                query += f" AND {extra}"
            row = connection.execute(query, (run_id, case_id, ref.artifact_id)).fetchone()
        if row is None:
            raise ContractViolation("backlog stage input does not exist in the case scope")
        if _row_str(row, "source_sha256") != expected_sha256:
            raise RepositoryIntegrityError(
                "backlog stage input hash differs from the persisted root"
            )
