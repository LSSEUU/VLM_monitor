"""Dedicated SQLite persistence for M4 hearing authority.

This adapter composes the frozen M2 SQLite foundation instead of adding M4 SQL
and state reconstruction responsibilities to that module.
"""

from __future__ import annotations

import hashlib
import sqlite3
from datetime import UTC, datetime, timedelta
from itertools import pairwise
from typing import TYPE_CHECKING, Protocol

from pydantic import ValidationError

from labcourt.contracts.backlog import BacklogItem, BacklogLeaseIdentity
from labcourt.contracts.canonical import canonical_json, sha256_hex
from labcourt.contracts.cases import Case, TimelineEntry
from labcourt.contracts.detections import Detection, FrameBundle
from labcourt.contracts.enums import (
    AcquisitionAction,
    AcquisitionExecutionClaimState,
    AcquisitionExecutionMode,
    ArtifactKind,
    AuditAction,
    AuditActorRole,
    BacklogReasonCode,
    BacklogStage,
    BacklogStatus,
    CaseStatus,
    ClosureDefectCode,
    ModelParseStatus,
    VerificationStatus,
    VlmRole,
)
from labcourt.contracts.evidence import Crop, EvidencePack, EvidencePackDraft
from labcourt.contracts.frames import FrameRef
from labcourt.contracts.hearing import (
    AcquisitionExecutionClaimAuthority,
    AcquisitionExecutionPublication,
    AcquisitionRequest,
    EvidencePackDerivation,
    HearingBacklogCompletionReceipt,
    HearingBacklogRetryFailure,
    HearingBacklogRetryOutcome,
    HearingBacklogRetrySuccess,
    HearingCheckpoint,
    HearingCheckpointPhase,
    HearingCycleScope,
    HearingHumanReviewReason,
    HearingHumanReviewReceipt,
    HearingInitialStrictParseFailureProof,
    HearingModelCacheEntry,
    HearingModelCallFailureAuthority,
    HearingModelParseReceipt,
    HearingModelRequest,
    HearingModelResponse,
    HearingPrecedentRetrievalReceipt,
    HearingRecord,
    HearingReworkReceipt,
    HearingRoleOutput,
    HearingRound,
    HearingSession,
    HearingSessionEntryStatus,
    HearingStrictParseFailureAttempt,
    HearingStrictParseFailureProof,
    HearingUsageReceipt,
    HearingVerdictBinding,
    JudgeAcquisitionDecisionPayload,
    JudgeFinalDecisionPayload,
    JudgeModelPayload,
    ToolExecutionManifest,
    ToolExecutionReceipt,
    validate_hearing_cycle_scope_binding,
)
from labcourt.contracts.model_call_failures import (
    ModelCallFailureClosureKind,
    VLMDeliveryCertainty,
)
from labcourt.contracts.references import require_reference_token
from labcourt.contracts.storage import (
    ArtifactRef,
    ArtifactVerification,
    ClosureDefect,
    ClosureReport,
)
from labcourt.contracts.verdicts import ProceduralDefect, ProceduralReview, Verdict
from labcourt.domain.evidence_authority import (
    AcquisitionAuthorityError,
    AcquisitionExecution,
    EvidenceAuthority,
    EvidenceAuthorityError,
    EvidencePackSuccessorError,
    LoadedEvidenceObjects,
    derive_evidence_authority,
    derive_evidence_pack_successor,
    merge_loaded_evidence_objects,
    validate_evidence_pack_successor,
)
from labcourt.domain.hearing_fsm import HearingCallClosure
from labcourt.exceptions import (
    ConcurrentModification,
    ContractViolation,
    CreationClosureFailed,
    EvidenceMissing,
    ManifestMismatch,
)
from labcourt.ports.evidence_repository import AuditHead, CaseSnapshot, EvidenceVerifier
from labcourt.ports.hearing_backlog import (
    HearingBacklogEnqueueCommit,
    HearingBacklogEnqueueIntent,
    HearingBacklogRetryAuthority,
    HearingBacklogRetryCommit,
    HearingModelCallFailureIntent,
)
from labcourt.ports.hearing_repository import (
    AcquisitionExecutionClaim,
    AcquisitionExecutionClaimStatus,
    AcquisitionExecutionCommit,
    AcquisitionPublishResult,
    HearingBudgetUsage,
    HearingHumanReviewResult,
    HearingModelCallClaim,
    HearingModelCallClaimStatus,
    HearingPersistenceConflict,
    HearingReworkResult,
    HearingStartResult,
    HearingVerdictReviewResult,
)

from ._sqlite_read_session import SQLiteReadSession
from .sqlite_repository import (
    RepositoryIntegrityError,
    _canonical_utc_timestamp,
    _contract_document,
    _parse_utc_timestamp,
    _row_int,
    _row_optional_str,
    _row_str,
    _utc_timestamp,
    _verify_contract_document,
    _verify_document,
)

_ACQUISITION_EXECUTION_LEASE_SECONDS = 30

if TYPE_CHECKING:
    from collections.abc import Callable
    from contextlib import AbstractContextManager
    from typing import Any


class _SQLiteHearingHost(Protocol):
    _clock: Callable[[], datetime]
    _verifier: EvidenceVerifier | None

    def _immediate(
        self,
        *,
        require_m4: bool = False,
    ) -> AbstractContextManager[sqlite3.Connection]: ...

    def _connection(
        self,
        *,
        require_hardening: bool = True,
        require_m4: bool = False,
    ) -> sqlite3.Connection: ...

    def _fault(self, phase: str) -> None: ...

    def _load_case(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        case_id: str,
    ) -> Any: ...

    def _load_pack(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        pack_id: str,
    ) -> Any: ...

    def _load_frame(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        frame_id: str,
    ) -> Any: ...

    def _load_run_manifest(self, connection: sqlite3.Connection, run_id: str) -> Any: ...

    def _validated_head(self, connection: SQLiteReadSession, run_id: str) -> AuditHead: ...

    def _append_audit(
        self,
        connection: sqlite3.Connection,
        head: AuditHead,
        *,
        action: AuditAction,
        object_ref: ArtifactRef,
        before_sha256: str | None,
        after_sha256: str | None,
        actor: AuditActorRole = AuditActorRole.EVIDENCE,
        recorded_at: str | None = None,
    ) -> tuple[Any, AuditHead]: ...


class SQLiteHearingRepository:
    """M4-only SQLite transaction and typed-reload authority."""

    def __init__(self, host: _SQLiteHearingHost) -> None:
        self._host = host

    def commit_hearing_backlog(
        self,
        run_id: str,
        expected_case_revision: int,
        expected_audit_head: AuditHead,
        intent: HearingBacklogEnqueueIntent,
    ) -> HearingBacklogEnqueueCommit:
        """Atomically close one initial role failure and enqueue exact retry work."""

        require_reference_token(run_id, "hearing repository run_id")
        self._require_expected_case_revision(expected_case_revision)
        if not isinstance(expected_audit_head, AuditHead):
            raise TypeError("expected_audit_head must be an AuditHead")
        if not isinstance(intent, HearingBacklogEnqueueIntent):
            raise TypeError("intent must be a HearingBacklogEnqueueIntent")
        validated_item = BacklogItem.model_validate(intent.item.model_dump(mode="json"))
        validated_checkpoint = HearingCheckpoint.model_validate(
            intent.checkpoint.model_dump(mode="json")
        )
        validated_request = HearingModelRequest.model_validate(
            intent.stage_request.model_dump(mode="json")
        )
        strict_failure = (
            HearingInitialStrictParseFailureProof.model_validate(
                intent.strict_parse_failure.model_dump(mode="json")
            )
            if intent.strict_parse_failure is not None
            else None
        )
        validated_intent = HearingBacklogEnqueueIntent(
            item=validated_item,
            checkpoint=validated_checkpoint,
            stage_request=validated_request,
            model_call_failure=intent.model_call_failure,
            strict_parse_failure=strict_failure,
        )
        if (
            validated_item.run_id != run_id
            or validated_checkpoint.run_id != run_id
            or validated_request.run_id != run_id
        ):
            raise ContractViolation("hearing backlog enqueue belongs to another run")

        try:
            with self._host._immediate(require_m4=True) as connection:
                existing = connection.execute(
                    """
                    SELECT 1 FROM backlog_items
                    WHERE run_id = ? AND item_id = ?
                    """,
                    (run_id, validated_item.item_id),
                ).fetchone()
                if existing is not None:
                    return self._replay_hearing_backlog_enqueue(
                        connection,
                        run_id=run_id,
                        expected_case_revision=expected_case_revision,
                        expected_audit_head=expected_audit_head,
                        intent=validated_intent,
                    )

                loaded = self._host._load_case(
                    connection,
                    run_id,
                    validated_item.case_id,
                )
                snapshot = loaded.snapshot
                if snapshot.revision != expected_case_revision:
                    raise ConcurrentModification(
                        "case revision changed before hearing backlog enqueue"
                    )
                if (
                    snapshot.case.status != CaseStatus.DELIBERATING
                    or snapshot.case.current_backlog_item_id is not None
                ):
                    raise ConcurrentModification(
                        "initial hearing backlog requires a DELIBERATING Case"
                    )
                head = self._host._validated_head(connection, run_id)
                self._require_expected_head(head, expected_audit_head)
                self._require_initial_hearing_backlog_boundary(
                    connection,
                    snapshot=snapshot,
                    intent=validated_intent,
                )
                self._insert_hearing_backlog_item(connection, validated_item)
                self._host._fault("hearing.backlog.after_item")

                if strict_failure is not None:
                    self._insert_initial_strict_parse_failure(
                        connection,
                        item=validated_item,
                        proof=strict_failure,
                    )
                    self._host._fault("hearing.backlog.after_strict_failure")

                assert validated_item.role is not None
                new_case = self._case_with_updates(
                    snapshot.case,
                    status=CaseStatus.BACKLOGGED,
                    current_backlog_item_id=validated_item.item_id,
                    timeline_entry=TimelineEntry(
                        sequence=len(snapshot.case.timeline),
                        action=AuditAction.CASE_STATE_CHANGED.value,
                        stage="BACKLOG",
                        object_ref=validated_item.item_id,
                        details={
                            "reason_code": validated_item.reason_code.value,
                            "retry_generation": validated_item.retry_generation,
                            "role": validated_item.role.value,
                            "status": CaseStatus.BACKLOGGED.value,
                        },
                    ),
                )
                committed = self._commit_case_version(
                    connection,
                    previous=snapshot,
                    previous_document_sha256=loaded.document_sha256,
                    new_case=new_case,
                    expected_head=head,
                    object_ref=ArtifactRef(
                        kind=ArtifactKind.BACKLOG_ITEM,
                        artifact_id=validated_item.item_id,
                    ),
                    fault_prefix="hearing.backlog",
                )
                audit_head = self._audit_head_after_expected(
                    connection,
                    expected_audit_head,
                )

                failure_authority = None
                provider_failure = validated_intent.model_call_failure
                if provider_failure is not None:
                    failure_authority = self._build_initial_model_call_failure_authority(
                        provider_failure,
                        item=validated_item,
                        checkpoint=validated_checkpoint,
                        closure_case_revision=committed.revision,
                        audit_head=audit_head,
                    )
                    self._insert_model_call_failure_authority(
                        connection,
                        failure_authority,
                    )
                    self._host._fault("hearing.backlog.after_failure_authority")

                return HearingBacklogEnqueueCommit(
                    item=validated_item,
                    case=committed,
                    checkpoint=validated_checkpoint,
                    stage_request=validated_request,
                    audit_head=audit_head,
                    failure_authority=failure_authority,
                    strict_parse_failure=strict_failure,
                    created=True,
                )
        except sqlite3.IntegrityError as exc:
            raise ContractViolation("hearing backlog authority was rejected") from exc

    def lease_next_hearing_backlog(
        self,
        run_id: str,
        lease_owner_sha256: str,
        lease_expires_at: datetime,
    ) -> BacklogItem | None:
        """Lease the first current pending HEARING item in stable identity order."""

        require_reference_token(run_id, "hearing repository run_id")
        self._require_sha256(lease_owner_sha256, "lease_owner_sha256")
        expiry_text = _canonical_utc_timestamp(
            lease_expires_at,
            "hearing backlog lease expiry",
        )
        now = self._clock_datetime()
        if lease_expires_at <= now:
            raise ValueError("hearing backlog lease expiry must be in the future")
        try:
            with self._host._immediate(require_m4=True) as connection:
                row = connection.execute(
                    """
                    SELECT head.current_version, version.item_id
                    FROM backlog_heads AS head
                    JOIN backlog_item_versions AS version
                      ON version.run_id = head.run_id
                     AND version.item_id = head.item_id
                     AND version.version = head.current_version
                    JOIN backlog_items AS item
                      ON item.run_id = head.run_id
                     AND item.item_id = head.item_id
                    JOIN cases AS case_head
                      ON case_head.run_id = item.run_id
                     AND case_head.case_id = item.case_id
                    WHERE head.run_id = ?
                      AND item.stage = 'HEARING'
                      AND version.status = 'PENDING'
                      AND case_head.status = 'BACKLOGGED'
                    ORDER BY version.item_id
                    LIMIT 1
                    """,
                    (run_id,),
                ).fetchone()
                if row is None:
                    return None
                current = self._load_hearing_backlog_version(
                    connection,
                    run_id,
                    _row_str(row, "item_id"),
                    _row_int(row, "current_version"),
                )
                loaded = self._host._load_case(
                    connection,
                    run_id,
                    current.case_id,
                )
                if (
                    loaded.snapshot.case.status != CaseStatus.BACKLOGGED
                    or loaded.snapshot.case.current_backlog_item_id != current.item_id
                ):
                    raise RepositoryIntegrityError(
                        "pending hearing backlog item is not the current Case boundary"
                    )
                next_attempt = current.attempt_count + 1
                if next_attempt > current.max_attempts:
                    raise RepositoryIntegrityError(
                        "pending hearing backlog item exceeds its retry budget"
                    )
                lease_id = sha256_hex(
                    [
                        "hearing-backlog-lease",
                        1,
                        run_id,
                        current.item_id,
                        next_attempt,
                        current.retry_generation,
                        lease_owner_sha256,
                        expiry_text,
                    ]
                )
                leased = BacklogItem.model_validate(
                    {
                        **current.model_dump(mode="json", exclude_computed_fields=True),
                        "attempt_count": next_attempt,
                        "status": BacklogStatus.LEASED.value,
                        "lease_id": lease_id,
                        "lease_owner_sha256": lease_owner_sha256,
                        "lease_expires_at": expiry_text,
                    }
                )
                self._advance_hearing_backlog(connection, current, leased)
                self._host._fault("hearing.backlog_retry.after_lease")
                return leased
        except sqlite3.IntegrityError as exc:
            raise ContractViolation("hearing backlog lease was rejected") from exc

    def load_hearing_backlog_retry_authority(
        self,
        run_id: str,
        lease: BacklogLeaseIdentity,
    ) -> HearingBacklogRetryAuthority:
        """Reconstruct one active retry authority from a single read snapshot."""

        require_reference_token(run_id, "hearing repository run_id")
        if not isinstance(lease, BacklogLeaseIdentity):
            raise TypeError("lease must be a BacklogLeaseIdentity")
        if lease.run_id != run_id:
            raise ContractViolation("hearing backlog lease belongs to another run")
        connection = self._host._connection(require_hardening=True, require_m4=True)
        try:
            connection.execute("BEGIN")
            return self._load_hearing_backlog_retry_authority(
                connection,
                run_id=run_id,
                lease=lease,
                allow_expired=False,
            )
        finally:
            connection.close()

    def commit_hearing_backlog_retry(
        self,
        run_id: str,
        expected_case_revision: int,
        expected_audit_head: AuditHead,
        outcome: HearingBacklogRetryOutcome,
        model_call_failure: HearingModelCallFailureIntent | None = None,
    ) -> HearingBacklogRetryCommit:
        """Atomically close one exact HEARING lease and its Case/audit boundary."""

        require_reference_token(run_id, "hearing repository run_id")
        self._require_expected_case_revision(expected_case_revision)
        if not isinstance(expected_audit_head, AuditHead):
            raise TypeError("expected_audit_head must be an AuditHead")
        validated = self._validated_hearing_backlog_outcome(outcome)
        if model_call_failure is not None and not isinstance(
            model_call_failure,
            HearingModelCallFailureIntent,
        ):
            raise TypeError("model_call_failure has the wrong intent type")
        if validated.lease.run_id != run_id:
            raise ContractViolation("hearing backlog outcome belongs to another run")
        try:
            with self._host._immediate(require_m4=True) as connection:
                return self._commit_hearing_backlog_retry(
                    connection,
                    run_id=run_id,
                    expected_case_revision=expected_case_revision,
                    expected_audit_head=expected_audit_head,
                    outcome=validated,
                    allow_expired=False,
                    model_call_failure=model_call_failure,
                )
        except sqlite3.IntegrityError as exc:
            raise ContractViolation("hearing backlog retry was rejected") from exc

    def reclaim_expired_hearing_backlog(
        self,
        run_id: str,
        not_after: datetime,
        limit: int,
    ) -> tuple[HearingBacklogRetryCommit, ...]:
        """Close expired HEARING leases in stable expiry/item order without a model call."""

        require_reference_token(run_id, "hearing repository run_id")
        cutoff_text = _canonical_utc_timestamp(not_after, "hearing backlog reclaim cutoff")
        cutoff = _parse_utc_timestamp(cutoff_text, "hearing backlog reclaim cutoff")
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 10_000:
            raise ValueError("hearing backlog reclaim limit must be in [1, 10000]")
        try:
            with self._host._immediate(require_m4=True) as connection:
                rows = connection.execute(
                    """
                    SELECT head.current_version, version.item_id
                    FROM backlog_heads AS head
                    JOIN backlog_item_versions AS version
                      ON version.run_id = head.run_id
                     AND version.item_id = head.item_id
                     AND version.version = head.current_version
                    JOIN backlog_items AS item
                      ON item.run_id = head.run_id
                     AND item.item_id = head.item_id
                    JOIN cases AS case_head
                      ON case_head.run_id = item.run_id
                     AND case_head.case_id = item.case_id
                    WHERE head.run_id = ?
                      AND item.stage = 'HEARING'
                      AND version.status = 'LEASED'
                      AND version.lease_expires_at <= ?
                      AND case_head.status = 'BACKLOGGED'
                    ORDER BY version.lease_expires_at, version.item_id
                    LIMIT ?
                    """,
                    (run_id, cutoff_text, limit),
                ).fetchall()
                commits: list[HearingBacklogRetryCommit] = []
                for row in rows:
                    current = self._load_hearing_backlog_version(
                        connection,
                        run_id,
                        _row_str(row, "item_id"),
                        _row_int(row, "current_version"),
                    )
                    if (
                        current.lease_id is None
                        or current.lease_expires_at is None
                        or current.lease_expires_at > cutoff
                    ):
                        raise ConcurrentModification(
                            "hearing backlog lease is not expired under the reclaim cutoff"
                        )
                    lease = BacklogLeaseIdentity(
                        run_id=current.run_id,
                        item_id=current.item_id,
                        lease_id=current.lease_id,
                        attempt_count=current.attempt_count,
                        retry_generation=current.retry_generation,
                    )
                    authority = self._load_hearing_backlog_retry_authority(
                        connection,
                        run_id=run_id,
                        lease=lease,
                        allow_expired=True,
                    )
                    next_status = (
                        BacklogStatus.EXHAUSTED
                        if current.attempt_count == current.max_attempts
                        else BacklogStatus.PENDING
                    )
                    human = (
                        self._backlog_exhaustion_receipt(authority)
                        if next_status == BacklogStatus.EXHAUSTED
                        else None
                    )
                    resume_ref = (
                        ArtifactRef(
                            kind=ArtifactKind.MODEL_REQUEST,
                            artifact_id=authority.unfinished_request.request_id,
                        )
                        if authority.unfinished_request is not None
                        else None
                    )
                    failure = HearingBacklogRetryFailure(
                        lease=lease,
                        source_checkpoint_id=authority.checkpoint.checkpoint_id,
                        source_checkpoint_sha256=authority.checkpoint.checkpoint_sha256,
                        source_checkpoint_version=authority.checkpoint.version,
                        request=authority.stage_request,
                        request_binding="BACKLOG_STAGE_INPUT",
                        lease_expiry_resume_request_ref=resume_ref,
                        role=current.role,
                        reason_code=BacklogReasonCode.WORKER_LEASE_EXPIRED,
                        next_status=next_status,
                        human_review_receipt=human,
                        manifest_id=current.manifest_id,
                    )
                    commits.append(
                        self._commit_hearing_backlog_retry(
                            connection,
                            run_id=run_id,
                            expected_case_revision=authority.case.revision,
                            expected_audit_head=authority.audit_head,
                            outcome=failure,
                            allow_expired=True,
                        )
                    )
                return tuple(commits)
        except sqlite3.IntegrityError as exc:
            raise ContractViolation("hearing backlog reclaim was rejected") from exc

    def begin_hearing_case(
        self,
        run_id: str,
        expected_case_revision: int,
        expected_audit_head: AuditHead,
        session: HearingSession,
        cycle_scope: HearingCycleScope,
        checkpoint: HearingCheckpoint,
    ) -> HearingStartResult:
        """Atomically open one hearing and move its exact Case to DELIBERATING."""

        require_reference_token(run_id, "hearing repository run_id")
        self._require_expected_case_revision(expected_case_revision)
        validated_session = HearingSession.model_validate(session.model_dump(mode="json"))
        validated_cycle = HearingCycleScope.model_validate(cycle_scope.model_dump(mode="json"))
        validated_checkpoint = HearingCheckpoint.model_validate(checkpoint.model_dump(mode="json"))
        self._validate_initial_hearing_roots(
            run_id,
            validated_session,
            validated_cycle,
            validated_checkpoint,
        )

        try:
            with self._host._immediate(require_m4=True) as connection:
                existing = connection.execute(
                    "SELECT 1 FROM m4_hearings WHERE run_id = ? AND hearing_id = ?",
                    (run_id, validated_session.session_id),
                ).fetchone()
                if existing is not None:
                    return self._replay_hearing_start(
                        connection,
                        run_id=run_id,
                        expected_case_revision=expected_case_revision,
                        expected_audit_head=expected_audit_head,
                        session=validated_session,
                        cycle=validated_cycle,
                        checkpoint=validated_checkpoint,
                    )

                loaded = self._host._load_case(connection, run_id, validated_session.case_id)
                case = loaded.snapshot.case
                if loaded.snapshot.revision != expected_case_revision:
                    raise ConcurrentModification("case revision changed before hearing start")
                head = self._host._validated_head(connection, run_id)
                self._require_expected_head(head, expected_audit_head)
                self._validate_hearing_entry_case(case, validated_session)

                new_case = self._case_with_updates(
                    case,
                    status=CaseStatus.DELIBERATING,
                    timeline_entry=TimelineEntry(
                        sequence=len(case.timeline),
                        action=AuditAction.CASE_STATE_CHANGED.value,
                        stage="HEARING",
                        object_ref=validated_session.session_id,
                        details={"status": CaseStatus.DELIBERATING.value},
                    ),
                )
                committed = self._commit_case_version(
                    connection,
                    previous=loaded.snapshot,
                    previous_document_sha256=loaded.document_sha256,
                    new_case=new_case,
                    expected_head=head,
                    object_ref=ArtifactRef(
                        kind=ArtifactKind.CASE,
                        artifact_id=validated_session.case_id,
                    ),
                    fault_prefix="hearing.begin",
                )
                self._insert_hearing_session(connection, validated_session)
                self._host._fault("hearing.begin.after_session")
                self._insert_hearing_cycle(connection, validated_cycle)
                self._host._fault("hearing.begin.after_cycle")
                self._insert_hearing_checkpoint(connection, validated_checkpoint)
                self._host._fault("hearing.begin.after_checkpoint")
                self._host._fault("hearing.begin.before_commit")
                return HearingStartResult(
                    case=committed,
                    session=validated_session,
                    cycle=validated_cycle,
                    checkpoint=validated_checkpoint,
                    created=True,
                )
        except sqlite3.IntegrityError as exc:
            raise ContractViolation("hearing start transaction was rejected") from exc

    def start_hearing(
        self,
        run_id: str,
        session: HearingSession,
        cycle_scope: HearingCycleScope,
        checkpoint: HearingCheckpoint,
    ) -> None:
        """Atomically persist the immutable session, first cycle, and first checkpoint."""

        require_reference_token(run_id, "hearing repository run_id")
        validated_session = HearingSession.model_validate(session.model_dump(mode="json"))
        validated_cycle = HearingCycleScope.model_validate(cycle_scope.model_dump(mode="json"))
        validated_checkpoint = HearingCheckpoint.model_validate(checkpoint.model_dump(mode="json"))
        self._validate_initial_hearing_roots(
            run_id,
            validated_session,
            validated_cycle,
            validated_checkpoint,
        )

        try:
            with self._host._immediate(require_m4=True) as connection:
                existing = connection.execute(
                    "SELECT 1 FROM m4_hearings WHERE run_id = ? AND hearing_id = ?",
                    (run_id, validated_session.session_id),
                ).fetchone()
                if existing is not None:
                    if (
                        self._load_hearing_session(
                            connection,
                            run_id,
                            validated_session.session_id,
                        )
                        != validated_session
                        or self._load_hearing_cycle(
                            connection,
                            run_id,
                            validated_cycle.cycle_id,
                        )
                        != validated_cycle
                        or self._load_hearing_checkpoint(
                            connection,
                            run_id,
                            validated_checkpoint.checkpoint_id,
                        )
                        != validated_checkpoint
                    ):
                        raise HearingPersistenceConflict(
                            "hearing start identity conflicts with persisted content"
                        )
                    return
                self._insert_hearing_session(connection, validated_session)
                self._insert_hearing_cycle(connection, validated_cycle)
                self._insert_hearing_checkpoint(connection, validated_checkpoint)
                self._host._fault("hearing.start.before_commit")
        except sqlite3.IntegrityError as exc:
            raise ContractViolation("hearing start authority was rejected") from exc

    @staticmethod
    def _validate_initial_hearing_roots(
        run_id: str,
        session: HearingSession,
        cycle: HearingCycleScope,
        checkpoint: HearingCheckpoint,
    ) -> None:
        if (
            session.run_id != run_id
            or cycle.run_id != run_id
            or checkpoint.run_id != run_id
            or cycle.case_id != session.case_id
            or cycle.hearing_session_id != session.session_id
            or cycle.cycle_index != 1
            or cycle.prior_acquisition_rounds != 0
            or cycle.prior_rework_rounds != 0
            or cycle.cycle_evidence_pack_id != session.initial_evidence_pack_id
            or cycle.cycle_evidence_pack_version != session.initial_evidence_pack_version
            or cycle.initial_trigger_review_ref != session.initial_trigger_review_ref
            or cycle.initial_defect_codes != session.initial_defect_codes
            or cycle.manifest_id != session.manifest_id
            or checkpoint.hearing_session_sha256 != session.session_sha256
            or checkpoint.version != 1
        ):
            raise ContractViolation("hearing start artifacts do not share one initial scope")
        try:
            validate_hearing_cycle_scope_binding(cycle, checkpoint)
        except (TypeError, ValueError) as exc:
            raise ContractViolation("hearing checkpoint does not bind its first cycle") from exc

    @staticmethod
    def _validate_hearing_entry_case(case: Case, session: HearingSession) -> None:
        if (
            case.run_id != session.run_id
            or case.case_id != session.case_id
            or case.manifest_id != session.manifest_id
            or case.status.value != session.entry_status.value
            or not case.evidence_packs
            or case.evidence_packs[-1].pack_id != session.initial_evidence_pack_id
            or case.evidence_packs[-1].version != session.initial_evidence_pack_version
            or not case.screening_results
            or case.screening_results[-1].screening_id != session.screening_id
        ):
            raise ConcurrentModification(
                "hearing session does not bind the latest eligible Case authority"
            )
        if session.entry_status == HearingSessionEntryStatus.ESCALATED:
            return
        if not case.verdicts or not case.procedural_reviews:
            raise ContractViolation("rework entry requires the latest failed review")
        review = case.procedural_reviews[-1]
        verdict = case.verdicts[-1]
        trigger = session.initial_trigger_review_ref
        if (
            review.passed
            or trigger is None
            or trigger.artifact_id != review.review_id
            or review.reviewed_verdict_id != verdict.verdict_id
            or review.evidence_pack_id != session.initial_evidence_pack_id
            or review.evidence_pack_version != session.initial_evidence_pack_version
            or session.initial_defect_codes != tuple(defect.code for defect in review.defects)
        ):
            raise ContractViolation(
                "rework hearing entry does not bind the exact latest failed review"
            )

    def _replay_hearing_start(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        expected_case_revision: int,
        expected_audit_head: AuditHead,
        session: HearingSession,
        cycle: HearingCycleScope,
        checkpoint: HearingCheckpoint,
    ) -> HearingStartResult:
        if (
            self._load_hearing_session(connection, run_id, session.session_id) != session
            or self._load_hearing_cycle(connection, run_id, cycle.cycle_id) != cycle
            or self._load_hearing_checkpoint(connection, run_id, checkpoint.checkpoint_id)
            != checkpoint
        ):
            raise HearingPersistenceConflict(
                "hearing start identity conflicts with persisted content"
            )
        committed = self._load_case_revision(
            connection,
            run_id,
            session.case_id,
            expected_case_revision + 1,
        )
        if (
            committed.case.status != CaseStatus.DELIBERATING
            or not committed.case.timeline
            or committed.case.timeline[-1].object_ref != session.session_id
        ):
            raise RepositoryIntegrityError(
                "persisted hearing roots lack their exact Case transition"
            )
        self._verify_transition_audit(
            connection,
            run_id=run_id,
            audit_sequence=expected_audit_head.sequence + 1,
            expected_head=expected_audit_head,
            object_id=session.case_id,
            object_kind=ArtifactKind.CASE,
        )
        return HearingStartResult(
            case=committed,
            session=session,
            cycle=cycle,
            checkpoint=checkpoint,
            created=False,
        )

    def append_hearing_cycle(
        self,
        run_id: str,
        cycle_scope: HearingCycleScope,
    ) -> None:
        require_reference_token(run_id, "hearing repository run_id")
        validated = HearingCycleScope.model_validate(cycle_scope.model_dump(mode="json"))
        if validated.run_id != run_id:
            raise ContractViolation("hearing cycle belongs to another run")
        try:
            with self._host._immediate(require_m4=True) as connection:
                row = connection.execute(
                    "SELECT 1 FROM m4_hearing_cycles WHERE run_id = ? AND cycle_id = ?",
                    (run_id, validated.cycle_id),
                ).fetchone()
                if row is not None:
                    stored = self._load_hearing_cycle(
                        connection,
                        run_id,
                        validated.cycle_id,
                    )
                    if stored != validated:
                        raise HearingPersistenceConflict(
                            "hearing cycle identity conflicts with persisted content"
                        )
                    return
                self._insert_hearing_cycle(connection, validated)
                self._host._fault("hearing.cycle.before_commit")
        except sqlite3.IntegrityError as exc:
            raise ContractViolation("hearing cycle authority was rejected") from exc

    def append_hearing_checkpoint(
        self,
        run_id: str,
        checkpoint: HearingCheckpoint,
    ) -> None:
        require_reference_token(run_id, "hearing repository run_id")
        validated = HearingCheckpoint.model_validate(checkpoint.model_dump(mode="json"))
        if validated.run_id != run_id:
            raise ContractViolation("hearing checkpoint belongs to another run")
        try:
            with self._host._immediate(require_m4=True) as connection:
                scope = self._load_hearing_cycle(
                    connection,
                    run_id,
                    validated.cycle_scope_id,
                )
                validate_hearing_cycle_scope_binding(scope, validated)
                row = connection.execute(
                    "SELECT 1 FROM m4_hearing_checkpoints WHERE run_id = ? AND checkpoint_id = ?",
                    (run_id, validated.checkpoint_id),
                ).fetchone()
                if row is not None:
                    if (
                        self._load_hearing_checkpoint(
                            connection,
                            run_id,
                            validated.checkpoint_id,
                        )
                        != validated
                    ):
                        raise HearingPersistenceConflict(
                            "hearing checkpoint identity conflicts with persisted content"
                        )
                    return
                if validated.acquisition_request is not None:
                    self._insert_or_validate_acquisition_request(
                        connection,
                        validated.acquisition_request,
                        cycle_scope_id=validated.cycle_scope_id,
                        cycle_scope_sha256=validated.cycle_scope_sha256,
                    )
                self._insert_hearing_checkpoint(connection, validated)
                self._host._fault("hearing.checkpoint.before_commit")
        except sqlite3.IntegrityError as exc:
            raise ContractViolation("hearing checkpoint authority was rejected") from exc

    def append_precedent_retrieval(
        self,
        run_id: str,
        receipt: HearingPrecedentRetrievalReceipt,
    ) -> None:
        try:
            with self._host._immediate(require_m4=True) as connection:
                self._append_precedent_retrieval_in_connection(
                    connection,
                    run_id,
                    receipt,
                )
                self._host._fault("hearing.retrieval.before_commit")
        except sqlite3.IntegrityError as exc:
            raise ContractViolation("precedent retrieval authority was rejected") from exc

    def _append_precedent_retrieval_in_connection(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        receipt: HearingPrecedentRetrievalReceipt,
    ) -> HearingPrecedentRetrievalReceipt:
        """Append using the caller's transaction and return its canonical authority."""

        if not isinstance(connection, sqlite3.Connection) or not connection.in_transaction:
            raise ContractViolation(
                "precedent retrieval append requires an active SQLite transaction"
            )
        require_reference_token(run_id, "hearing repository run_id")
        validated = HearingPrecedentRetrievalReceipt.model_validate(receipt.model_dump(mode="json"))
        if validated.run_id != run_id:
            raise ContractViolation("precedent retrieval belongs to another run")
        scope = self._load_hearing_cycle(
            connection,
            run_id,
            validated.cycle_scope_id,
        )
        validate_hearing_cycle_scope_binding(scope, validated)
        row = connection.execute(
            """
            SELECT receipt_json, document_sha256
            FROM m4_precedent_retrieval_receipts
            WHERE run_id = ? AND retrieval_receipt_id = ?
            """,
            (run_id, validated.receipt_id),
        ).fetchone()
        document = _contract_document(validated)
        if row is not None:
            durable = self._load_precedent_retrieval(
                connection,
                run_id,
                validated.receipt_id,
            )
            if (
                durable != validated
                or _row_str(row, "receipt_json") != document
                or _row_str(row, "document_sha256") != validated.receipt_sha256
            ):
                raise HearingPersistenceConflict(
                    "precedent retrieval identity conflicts with persisted content"
                )
            return durable
        self._insert_precedent_retrieval(connection, validated, document)
        return validated

    def claim_hearing_model_call(
        self,
        run_id: str,
        request: HearingModelRequest,
        owner_token: str,
        backlog_lease: BacklogLeaseIdentity | None = None,
    ) -> HearingModelCallClaim:
        """Reserve one exact role call and its image disclosure exactly once."""

        require_reference_token(run_id, "hearing repository run_id")
        validated = HearingModelRequest.model_validate(request.model_dump(mode="json"))
        if validated.run_id != run_id:
            raise ContractViolation("hearing model request belongs to another run")
        if not isinstance(owner_token, str) or not 32 <= len(owner_token) <= 512:
            raise ValueError("hearing model claim owner token has an invalid length")
        context = validated.backlog_retry_context
        if backlog_lease is not None:
            if (
                not isinstance(backlog_lease, BacklogLeaseIdentity)
                or backlog_lease.run_id != run_id
                or (
                    context is not None
                    and (
                        backlog_lease.item_id != context.backlog_item_id
                        or backlog_lease.retry_generation != context.retry_generation
                    )
                )
            ):
                raise ContractViolation(
                    "hearing retry model call requires its exact backlog lease identity"
                )
        elif context is not None:
            raise ContractViolation("hearing retry model call requires its active backlog lease")
        owner_sha256 = hashlib.sha256(owner_token.encode("utf-8")).hexdigest()
        try:
            now = self._host._clock()
            now_text = _canonical_utc_timestamp(now, "repository clock")
            expiry = now.astimezone(UTC) + timedelta(seconds=validated.budget.claim_lease_seconds)
            expiry_text = _canonical_utc_timestamp(expiry, "hearing claim expiry")
        except (TypeError, ValueError) as exc:
            raise ContractViolation(
                "repository clock must return a timezone-aware datetime"
            ) from exc

        try:
            with self._host._immediate(require_m4=True) as connection:
                rows = connection.execute(
                    """
                    SELECT * FROM m4_model_call_claims
                    WHERE run_id = ? AND (request_id = ? OR cache_key = ?)
                    """,
                    (run_id, validated.request_id, validated.cache_key),
                ).fetchall()
                if len(rows) > 1:
                    raise RepositoryIntegrityError(
                        "hearing request identities select multiple claims"
                    )
                if rows:
                    row = rows[0]
                    stored = self._hearing_model_request_from_claim_row(row)
                    if stored != validated:
                        raise HearingPersistenceConflict(
                            "hearing request identity conflicts with persisted content"
                        )
                    claim = self._hearing_model_claim_from_row(
                        row,
                        now=now.astimezone(UTC),
                    )
                    if claim.status == HearingModelCallClaimStatus.COMPLETED:
                        return claim
                    if (
                        backlog_lease is not None
                        and owner_sha256 != _row_str(row, "owner_token_sha256")
                        and self._known_hearing_failure_authorizes_retry(
                            connection,
                            row=row,
                            request=validated,
                            backlog_lease=backlog_lease,
                        )
                    ):
                        previous_owner = _row_str(row, "owner_token_sha256")
                        previous_expiry = _row_str(row, "lease_expires_at")
                        previous_takeover_count = _row_int(row, "takeover_count")
                        previous_expiry_value = _parse_utc_timestamp(
                            previous_expiry,
                            "hearing model claim previous expiry",
                        )
                        takeover_expiry = max(
                            expiry,
                            previous_expiry_value + timedelta(microseconds=1),
                        )
                        takeover_expiry_text = _canonical_utc_timestamp(
                            takeover_expiry,
                            "hearing model claim takeover expiry",
                        )
                        updated = connection.execute(
                            """
                            UPDATE m4_model_call_claims
                            SET owner_token_sha256 = ?, lease_expires_at = ?,
                                takeover_count = takeover_count + 1
                            WHERE run_id = ? AND request_id = ? AND status = 'ACTIVE'
                              AND owner_token_sha256 = ? AND lease_expires_at = ?
                              AND takeover_count = ?
                              AND response_id IS NULL AND completed_at IS NULL
                            """,
                            (
                                owner_sha256,
                                takeover_expiry_text,
                                run_id,
                                validated.request_id,
                                previous_owner,
                                previous_expiry,
                                previous_takeover_count,
                            ),
                        )
                        if updated.rowcount != 1:
                            raise ConcurrentModification(
                                "known-failure hearing model call retry CAS was lost"
                            )
                        self._host._fault("hearing.model.claim.after_known_failure_takeover")
                        return HearingModelCallClaim(
                            status=HearingModelCallClaimStatus.ACQUIRED,
                            request_id=validated.request_id,
                            lease_expires_at=takeover_expiry,
                            takeover_count=previous_takeover_count + 1,
                        )
                    return claim

                if backlog_lease is not None:
                    if context is None and validated.attempt_index == 0:
                        raise ContractViolation(
                            "generation-zero retry cannot create a missing model claim"
                        )
                    authority = self._load_hearing_backlog_retry_authority(
                        connection,
                        run_id=run_id,
                        lease=backlog_lease,
                        allow_expired=False,
                    )
                    if (
                        (
                            context is not None
                            and (
                                authority.item.item_id != context.backlog_item_id
                                or authority.item.retry_generation != context.retry_generation
                            )
                        )
                        or (
                            context is None
                            and (
                                authority.item.retry_generation != 0
                                or validated.original_request_id
                                != authority.primary_template_request.request_id
                            )
                        )
                        or authority.item.case_id != validated.case_id
                        or authority.item.role != validated.role
                    ):
                        raise ContractViolation(
                            "hearing model request crosses its active backlog authority"
                        )

                self._validate_hearing_model_request_order(connection, validated)
                request_json = _contract_document(validated)
                request_document_sha256 = hashlib.sha256(request_json.encode("utf-8")).hexdigest()
                connection.execute(
                    """
                    INSERT INTO m4_model_call_claims(
                        run_id, request_id, request_sha256, cache_key,
                        hearing_id, cycle_scope_id, cycle_scope_sha256, case_id,
                        role, purpose, attempt_index, call_generation,
                        backlog_item_id, retry_generation,
                        reserved_images, reserved_pixels,
                        evidence_pack_id, evidence_pack_version,
                        model_manifest_id, prompt_manifest_id, manifest_id,
                        request_json, request_document_sha256,
                        status, owner_token_sha256, lease_expires_at,
                        takeover_count, created_at, response_id, completed_at
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        'ACTIVE', ?, ?, 0, ?, NULL, NULL
                    )
                    """,
                    (
                        run_id,
                        validated.request_id,
                        validated.request_sha256,
                        validated.cache_key,
                        validated.hearing_session_id,
                        validated.cycle_scope_id,
                        validated.cycle_scope_sha256,
                        validated.case_id,
                        validated.role.value,
                        self._hearing_model_call_purpose(validated),
                        validated.attempt_index,
                        "BACKLOG" if context is not None else "INITIAL",
                        context.backlog_item_id if context is not None else None,
                        context.retry_generation if context is not None else 0,
                        len(validated.media),
                        sum(item.width * item.height for item in validated.media),
                        validated.current_evidence_pack_id,
                        validated.current_evidence_pack_version,
                        validated.model_manifest_id,
                        validated.prompt_manifest.prompt_manifest_id,
                        validated.manifest_id,
                        request_json,
                        request_document_sha256,
                        owner_sha256,
                        expiry_text,
                        now_text,
                    ),
                )
                self._host._fault("hearing.model.claim.before_commit")
                return HearingModelCallClaim(
                    status=HearingModelCallClaimStatus.ACQUIRED,
                    request_id=validated.request_id,
                    lease_expires_at=expiry,
                )
        except sqlite3.IntegrityError as exc:
            raise ContractViolation("hearing model claim authority was rejected") from exc

    def complete_hearing_model_call(
        self,
        run_id: str,
        request: HearingModelRequest,
        response: HearingModelResponse,
        usage: HearingUsageReceipt,
        owner_token: str,
    ) -> HearingModelCacheEntry:
        """Atomically persist response/cache/usage and complete its exact claim."""

        require_reference_token(run_id, "hearing repository run_id")
        validated_request = HearingModelRequest.model_validate(request.model_dump(mode="json"))
        validated_response = HearingModelResponse.model_validate(response.model_dump(mode="json"))
        validated_usage = HearingUsageReceipt.model_validate(usage.model_dump(mode="json"))
        if validated_request.run_id != run_id:
            raise ContractViolation("hearing model request belongs to another run")
        if not isinstance(owner_token, str) or not 32 <= len(owner_token) <= 512:
            raise ValueError("hearing model claim owner token has an invalid length")
        owner_sha256 = hashlib.sha256(owner_token.encode("utf-8")).hexdigest()
        self._validate_hearing_model_completion(
            validated_request,
            validated_response,
            validated_usage,
        )
        completed_at = _utc_timestamp(self._host._clock)

        try:
            with self._host._immediate(require_m4=True) as connection:
                rows = connection.execute(
                    """
                    SELECT * FROM m4_model_call_claims
                    WHERE run_id = ? AND (request_id = ? OR cache_key = ?)
                    """,
                    (run_id, validated_request.request_id, validated_request.cache_key),
                ).fetchall()
                if len(rows) != 1:
                    raise ContractViolation(
                        "hearing model completion requires exactly one durable claim"
                    )
                row = rows[0]
                stored_request = self._hearing_model_request_from_claim_row(row)
                if stored_request != validated_request:
                    raise HearingPersistenceConflict(
                        "hearing model completion request conflicts with its claim"
                    )
                if _row_str(row, "status") == "COMPLETED":
                    return self._validate_completed_hearing_model_call(
                        connection,
                        validated_request,
                        validated_response,
                        validated_usage,
                    )
                if _row_str(row, "owner_token_sha256") != owner_sha256:
                    raise ConcurrentModification(
                        "hearing model completion owner no longer holds its claim"
                    )

                self._insert_hearing_model_response(
                    connection, validated_request, validated_response
                )
                self._host._fault("hearing.model.complete.after_response")
                updated = connection.execute(
                    """
                    UPDATE m4_model_call_claims
                    SET status = 'COMPLETED', response_id = ?, completed_at = ?
                    WHERE run_id = ? AND request_id = ? AND status = 'ACTIVE'
                      AND owner_token_sha256 = ?
                      AND response_id IS NULL AND completed_at IS NULL
                    """,
                    (
                        validated_response.response_id,
                        completed_at,
                        run_id,
                        validated_request.request_id,
                        owner_sha256,
                    ),
                )
                if updated.rowcount != 1:
                    raise ConcurrentModification("hearing model completion CAS was lost")
                cache_entry = self._insert_hearing_model_cache_entry(
                    connection,
                    validated_request,
                    validated_response,
                )
                self._insert_hearing_usage_receipt(
                    connection,
                    validated_request,
                    validated_response,
                    validated_usage,
                    accounted_at=completed_at,
                )
                self._host._fault("hearing.model.complete.before_commit")
                return cache_entry
        except sqlite3.IntegrityError as exc:
            raise ContractViolation("hearing model completion authority was rejected") from exc

    def append_hearing_parse_receipt(
        self,
        receipt: HearingModelParseReceipt,
        output: HearingRoleOutput | None = None,
    ) -> HearingModelParseReceipt:
        """Append one strict parse outcome and optional authoritative role output."""

        validated_receipt = HearingModelParseReceipt.model_validate(receipt.model_dump(mode="json"))
        validated_output = (
            HearingRoleOutput.model_validate(output.model_dump(mode="json"))
            if output is not None
            else None
        )
        self._validate_hearing_parse_binding(validated_receipt, validated_output)
        try:
            with self._host._immediate(require_m4=True) as connection:
                request = self._load_hearing_model_request(
                    connection,
                    validated_receipt.run_id,
                    validated_receipt.request_id,
                )
                response = self._load_hearing_model_response(
                    connection,
                    validated_receipt.run_id,
                    validated_receipt.response_id,
                )
                self._validate_hearing_parse_call_scope(
                    request,
                    response,
                    validated_receipt,
                )
                if validated_output is not None:
                    self._validate_hearing_role_output_scope(
                        connection,
                        request,
                        response,
                        validated_receipt,
                        validated_output,
                    )
                rows = connection.execute(
                    """
                    SELECT * FROM m4_model_parse_receipts
                    WHERE run_id = ? AND (parse_receipt_id = ? OR response_id = ?)
                    """,
                    (
                        validated_receipt.run_id,
                        validated_receipt.parse_receipt_id,
                        validated_receipt.response_id,
                    ),
                ).fetchall()
                if rows:
                    if len(rows) != 1:
                        raise RepositoryIntegrityError(
                            "hearing parse identities select multiple receipts"
                        )
                    stored = self._hearing_parse_receipt_from_row(rows[0])
                    if stored != validated_receipt:
                        raise HearingPersistenceConflict(
                            "hearing response already binds another parse receipt"
                        )
                    if (
                        validated_output is not None
                        and self._load_hearing_role_output(
                            connection,
                            validated_output.run_id,
                            validated_output.output_id,
                        )
                        != validated_output
                    ):
                        raise HearingPersistenceConflict(
                            "hearing output identity conflicts with persisted content"
                        )
                    return stored

                if validated_output is not None:
                    self._insert_hearing_role_output(
                        connection,
                        request,
                        validated_output,
                    )
                self._insert_hearing_parse_receipt(
                    connection,
                    validated_receipt,
                    validated_output,
                )
                self._host._fault("hearing.parse.before_commit")
                return validated_receipt
        except sqlite3.IntegrityError as exc:
            raise ContractViolation("hearing parse authority was rejected") from exc

    @staticmethod
    def _hearing_model_call_purpose(request: HearingModelRequest) -> str:
        return "ROLE_CALL" if request.attempt_index == 0 else "STRUCTURE_REPAIR"

    def _hearing_model_request_from_claim_row(
        self,
        row: sqlite3.Row,
    ) -> HearingModelRequest:
        raw = _row_str(row, "request_json")
        try:
            request = HearingModelRequest.model_validate_json(raw)
        except ValidationError as exc:
            raise RepositoryIntegrityError("stored hearing model request is invalid") from exc
        _verify_contract_document(raw, request)
        context = request.backlog_retry_context
        indexed = (
            request.run_id == _row_str(row, "run_id"),
            request.request_id == _row_str(row, "request_id"),
            request.request_sha256 == _row_str(row, "request_sha256"),
            request.cache_key == _row_str(row, "cache_key"),
            request.hearing_session_id == _row_str(row, "hearing_id"),
            request.cycle_scope_id == _row_str(row, "cycle_scope_id"),
            request.cycle_scope_sha256 == _row_str(row, "cycle_scope_sha256"),
            request.case_id == _row_str(row, "case_id"),
            request.role.value == _row_str(row, "role"),
            self._hearing_model_call_purpose(request) == _row_str(row, "purpose"),
            request.attempt_index == _row_int(row, "attempt_index"),
            ("BACKLOG" if context is not None else "INITIAL") == _row_str(row, "call_generation"),
            (context.backlog_item_id if context is not None else None) == row["backlog_item_id"],
            (context.retry_generation if context is not None else 0)
            == _row_int(row, "retry_generation"),
            len(request.media) == _row_int(row, "reserved_images"),
            sum(item.width * item.height for item in request.media)
            == _row_int(row, "reserved_pixels"),
            request.current_evidence_pack_id == _row_str(row, "evidence_pack_id"),
            request.current_evidence_pack_version == _row_int(row, "evidence_pack_version"),
            request.model_manifest_id == _row_str(row, "model_manifest_id"),
            request.prompt_manifest.prompt_manifest_id == _row_str(row, "prompt_manifest_id"),
            request.manifest_id == _row_str(row, "manifest_id"),
            hashlib.sha256(raw.encode("utf-8")).hexdigest()
            == _row_str(row, "request_document_sha256"),
        )
        if not all(indexed):
            raise RepositoryIntegrityError(
                "hearing model request indexes conflict with its document"
            )
        return request

    @staticmethod
    def _hearing_model_claim_from_row(
        row: sqlite3.Row,
        *,
        now: datetime,
    ) -> HearingModelCallClaim:
        status = _row_str(row, "status")
        request_id = _row_str(row, "request_id")
        takeover_count = _row_int(row, "takeover_count")
        if status == "COMPLETED":
            response_id = _row_str(row, "response_id")
            if row["completed_at"] is None:
                raise RepositoryIntegrityError(
                    "completed hearing model claim lacks completion time"
                )
            return HearingModelCallClaim(
                status=HearingModelCallClaimStatus.COMPLETED,
                request_id=request_id,
                response_id=response_id,
                takeover_count=takeover_count,
            )
        if status != "ACTIVE" or row["response_id"] is not None:
            raise RepositoryIntegrityError("hearing model claim has an invalid state")
        expiry = _parse_utc_timestamp(
            _row_str(row, "lease_expires_at"),
            "hearing model claim expiry",
        )
        return HearingModelCallClaim(
            status=(
                HearingModelCallClaimStatus.EXPIRED_REQUIRES_RECOVERY
                if expiry <= now
                else HearingModelCallClaimStatus.WAITING
            ),
            request_id=request_id,
            lease_expires_at=expiry,
            takeover_count=takeover_count,
        )

    def _known_hearing_failure_authorizes_retry(
        self,
        connection: sqlite3.Connection,
        *,
        row: sqlite3.Row,
        request: HearingModelRequest,
        backlog_lease: BacklogLeaseIdentity,
    ) -> bool:
        """Authorize one takeover from an exact, aggregate-closed unsent epoch."""

        authority = self._load_hearing_backlog_retry_authority(
            connection,
            run_id=request.run_id,
            lease=backlog_lease,
            allow_expired=False,
        )
        if authority.unfinished_request != request:
            return False
        rows = connection.execute(
            """
            SELECT * FROM m4_model_call_failure_authorities
            WHERE run_id = ? AND request_id = ?
              AND claim_owner_sha256 = ?
              AND claim_lease_expires_at = ?
              AND claim_takeover_count = ?
            """,
            (
                request.run_id,
                request.request_id,
                _row_str(row, "owner_token_sha256"),
                _row_str(row, "lease_expires_at"),
                _row_int(row, "takeover_count"),
            ),
        ).fetchall()
        if not rows:
            return False
        if len(rows) != 1:
            raise RepositoryIntegrityError(
                "hearing model claim epoch has multiple failure authorities"
            )
        failure = self._hearing_model_failure_authority_from_row(
            connection,
            rows[0],
        )
        item = authority.item
        if (
            failure.delivery_certainty != VLMDeliveryCertainty.DEFINITELY_NOT_SENT
            or failure.provider_response_content_sha256 is not None
            or failure.request != request
            or failure.backlog_item_id != item.item_id
            or failure.backlog_status != BacklogStatus.PENDING
            or failure.backlog_attempt_count >= item.attempt_count
            or failure.retry_generation != item.retry_generation
            or failure.source_checkpoint_id != authority.checkpoint.checkpoint_id
            or failure.source_checkpoint_sha256 != authority.checkpoint.checkpoint_sha256
            or failure.source_checkpoint_version != authority.checkpoint.version
            or failure.manifest_id != item.manifest_id
        ):
            return False
        if failure.closure_kind == ModelCallFailureClosureKind.INITIAL_BACKLOG:
            return failure.completion_receipt_id is None
        receipt_id = failure.completion_receipt_id
        return receipt_id is not None and any(
            receipt.receipt_id == receipt_id
            for receipt in self._load_hearing_backlog_completion_history(
                connection,
                run_id=request.run_id,
                item=item,
            )
        )

    def _validate_hearing_model_request_order(
        self,
        connection: sqlite3.Connection,
        request: HearingModelRequest,
    ) -> None:
        cycle = self._load_hearing_cycle(
            connection,
            request.run_id,
            request.cycle_scope_id,
        )
        validate_hearing_cycle_scope_binding(cycle, request)
        session = self._load_hearing_session(
            connection,
            request.run_id,
            request.hearing_session_id,
        )
        retrieval = self._load_precedent_retrieval(
            connection,
            request.run_id,
            request.precedent_retrieval_receipt_id,
        )
        expected_model = {
            VlmRole.PROSECUTOR: session.prosecutor_model_manifest_id,
            VlmRole.DEFENDER: session.defender_model_manifest_id,
            VlmRole.JUDGE: session.judge_model_manifest_id,
        }[request.role]
        if (
            request.precedent_retrieval_receipt_sha256 != retrieval.receipt_sha256
            or request.cycle_scope_id != retrieval.cycle_scope_id
            or request.cycle_scope_sha256 != retrieval.cycle_scope_sha256
            or request.hearing_prompt_bundle_sha256 != session.hearing_prompt_bundle_sha256
            or request.model_manifest_id != expected_model
        ):
            raise ContractViolation(
                "hearing model request conflicts with cycle retrieval or session authority"
            )
        context = request.backlog_retry_context
        retry_generation = context.retry_generation if context is not None else 0
        duplicate = connection.execute(
            """
            SELECT request_id FROM m4_model_call_claims
            WHERE run_id = ? AND cycle_scope_id = ? AND role = ?
              AND attempt_index = ? AND retry_generation = ?
            """,
            (
                request.run_id,
                request.cycle_scope_id,
                request.role.value,
                request.attempt_index,
                retry_generation,
            ),
        ).fetchone()
        if duplicate is not None:
            raise HearingPersistenceConflict(
                "hearing role attempt already has another durable request"
            )

        def require_output(output_id: str, role: VlmRole) -> HearingRoleOutput:
            output = self._load_hearing_role_output(connection, request.run_id, output_id)
            if (
                output.role != role
                or output.hearing_session_id != request.hearing_session_id
                or output.round_index != request.round_index
                or output.current_evidence_pack_id != request.current_evidence_pack_id
                or output.current_evidence_pack_version != request.current_evidence_pack_version
                or output.precedent_retrieval_receipt_id != request.precedent_retrieval_receipt_id
                or output.manifest_id != request.manifest_id
            ):
                raise ContractViolation(
                    "hearing model request cites an output outside its exact cycle"
                )
            return output

        if request.role == VlmRole.DEFENDER:
            assert request.prosecutor_output_ref is not None
            require_output(request.prosecutor_output_ref.artifact_id, VlmRole.PROSECUTOR)
        elif request.role == VlmRole.JUDGE:
            assert request.prosecutor_output_ref is not None
            assert request.defender_output_ref is not None
            prosecutor = require_output(
                request.prosecutor_output_ref.artifact_id,
                VlmRole.PROSECUTOR,
            )
            defender = require_output(
                request.defender_output_ref.artifact_id,
                VlmRole.DEFENDER,
            )
            if defender.prosecutor_output_id != prosecutor.output_id:
                raise ContractViolation("Judge request advocate outputs are not one ordered trace")

        if request.attempt_index == 1:
            assert request.original_request_id is not None
            assert request.original_response_id is not None
            primary = self._load_hearing_model_request(
                connection,
                request.run_id,
                request.original_request_id,
            )
            response = self._load_hearing_model_response(
                connection,
                request.run_id,
                request.original_response_id,
            )
            if (
                primary.attempt_index != 0
                or primary.role != request.role
                or primary.cycle_scope_id != request.cycle_scope_id
                or primary.backlog_retry_context != request.backlog_retry_context
                or response.request_id != primary.request_id
                or response.content_sha256 != request.original_response_content_sha256
            ):
                raise ContractViolation(
                    "hearing repair request lacks its exact completed primary call"
                )

    @staticmethod
    def _validate_hearing_model_completion(
        request: HearingModelRequest,
        response: HearingModelResponse,
        usage: HearingUsageReceipt,
    ) -> None:
        response_matches = (
            response.run_id == request.run_id
            and response.case_id == request.case_id
            and response.hearing_session_id == request.hearing_session_id
            and response.round_index == request.round_index
            and response.prior_acquisition_rounds == request.prior_acquisition_rounds
            and response.prior_rework_rounds == request.prior_rework_rounds
            and response.current_evidence_pack_id == request.current_evidence_pack_id
            and response.current_evidence_pack_version == request.current_evidence_pack_version
            and response.role == request.role
            and response.attempt_index == request.attempt_index
            and response.request_id == request.request_id
            and response.request_sha256 == request.request_sha256
            and response.cache_key == request.cache_key
            and response.model_manifest_id == request.model_manifest_id
            and response.manifest_id == request.manifest_id
        )
        expected_images = len(request.media)
        expected_pixels = sum(item.width * item.height for item in request.media)
        expected_cost = request.budget.estimate_cost(
            input_tokens=response.input_tokens,
            output_tokens=response.output_tokens,
        )
        usage_matches = (
            usage.run_id == request.run_id
            and usage.case_id == request.case_id
            and usage.hearing_session_id == request.hearing_session_id
            and usage.round_index == request.round_index
            and usage.role == request.role
            and usage.request_ref.kind == ArtifactKind.MODEL_REQUEST
            and usage.request_ref.artifact_id == request.request_id
            and usage.response_ref.kind == ArtifactKind.MODEL_RESPONSE
            and usage.response_ref.artifact_id == response.response_id
            and usage.input_images == expected_images
            and usage.input_pixels == expected_pixels
            and usage.input_tokens == response.input_tokens
            and usage.output_tokens == response.output_tokens
            and usage.latency_ms == response.latency_ms
            and usage.estimated_cost == expected_cost
            and usage.manifest_id == request.manifest_id
        )
        within_budget = (
            response.size_bytes <= request.budget.max_response_bytes
            and response.input_tokens <= request.budget.max_input_tokens
            and response.output_tokens <= request.budget.max_output_tokens
            and request.budget.allows_cost(
                input_tokens=response.input_tokens,
                output_tokens=response.output_tokens,
            )
        )
        if not response_matches or not usage_matches or not within_budget:
            raise ContractViolation("hearing response or usage conflicts with its exact request")

    def _insert_hearing_model_response(
        self,
        connection: sqlite3.Connection,
        request: HearingModelRequest,
        response: HearingModelResponse,
    ) -> None:
        document = _contract_document(response)
        context = request.backlog_retry_context
        connection.execute(
            """
            INSERT INTO m4_model_responses(
                run_id, response_id, request_id, request_sha256, cache_key,
                hearing_id, cycle_scope_id, cycle_scope_sha256, case_id,
                role, purpose, attempt_index, retry_generation,
                raw_response_ref, content_sha256, size_bytes,
                model_manifest_id, manifest_id, response_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                response.run_id,
                response.response_id,
                request.request_id,
                request.request_sha256,
                request.cache_key,
                request.hearing_session_id,
                request.cycle_scope_id,
                request.cycle_scope_sha256,
                request.case_id,
                request.role.value,
                self._hearing_model_call_purpose(request),
                request.attempt_index,
                context.retry_generation if context is not None else 0,
                response.raw_response_ref,
                response.content_sha256,
                response.size_bytes,
                response.model_manifest_id,
                response.manifest_id,
                document,
                hashlib.sha256(document.encode("utf-8")).hexdigest(),
            ),
        )

    @staticmethod
    def _hearing_cache_entry(
        request: HearingModelRequest,
        response: HearingModelResponse,
    ) -> HearingModelCacheEntry:
        return HearingModelCacheEntry(
            run_id=request.run_id,
            case_id=request.case_id,
            hearing_session_id=request.hearing_session_id,
            round_index=request.round_index,
            role=request.role,
            current_evidence_pack_id=request.current_evidence_pack_id,
            current_evidence_pack_version=request.current_evidence_pack_version,
            cache_key=request.cache_key,
            request_id=request.request_id,
            request_sha256=request.request_sha256,
            response_id=response.response_id,
            response_content_sha256=response.content_sha256,
            model_manifest_id=request.model_manifest_id,
            prompt_manifest_id=request.prompt_manifest.prompt_manifest_id,
            output_schema_sha256=request.prompt_manifest.output_schema_sha256,
            manifest_id=request.manifest_id,
        )

    def _insert_hearing_model_cache_entry(
        self,
        connection: sqlite3.Connection,
        request: HearingModelRequest,
        response: HearingModelResponse,
    ) -> HearingModelCacheEntry:
        entry = self._hearing_cache_entry(request, response)
        request_json = _contract_document(request)
        entry_json = _contract_document(entry)
        connection.execute(
            """
            INSERT INTO m4_model_cache(
                run_id, cache_key, cache_entry_id,
                hearing_id, cycle_scope_id, cycle_scope_sha256, case_id, role,
                request_id, request_sha256, response_id, response_content_sha256,
                model_manifest_id, prompt_manifest_id, output_schema_sha256,
                manifest_id, request_json, request_document_sha256,
                entry_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request.run_id,
                request.cache_key,
                entry.cache_entry_id,
                request.hearing_session_id,
                request.cycle_scope_id,
                request.cycle_scope_sha256,
                request.case_id,
                request.role.value,
                request.request_id,
                request.request_sha256,
                response.response_id,
                response.content_sha256,
                request.model_manifest_id,
                request.prompt_manifest.prompt_manifest_id,
                request.prompt_manifest.output_schema_sha256,
                request.manifest_id,
                request_json,
                hashlib.sha256(request_json.encode("utf-8")).hexdigest(),
                entry_json,
                hashlib.sha256(entry_json.encode("utf-8")).hexdigest(),
            ),
        )
        return entry

    @staticmethod
    def _insert_hearing_usage_receipt(
        connection: sqlite3.Connection,
        request: HearingModelRequest,
        response: HearingModelResponse,
        usage: HearingUsageReceipt,
        *,
        accounted_at: str,
    ) -> None:
        document = _contract_document(usage)
        connection.execute(
            """
            INSERT INTO m4_hearing_usage_receipts(
                run_id, usage_receipt_id, request_id, response_id,
                hearing_id, cycle_scope_id, cycle_scope_sha256, case_id, role,
                accounted_at, input_images, input_pixels,
                input_tokens, output_tokens, provider_latency_ms,
                retries, estimated_cost, manifest_id, usage_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                usage.run_id,
                usage.usage_receipt_id,
                request.request_id,
                response.response_id,
                request.hearing_session_id,
                request.cycle_scope_id,
                request.cycle_scope_sha256,
                usage.case_id,
                usage.role.value,
                accounted_at,
                usage.input_images,
                usage.input_pixels,
                usage.input_tokens,
                usage.output_tokens,
                usage.latency_ms,
                usage.retry_count,
                usage.estimated_cost,
                usage.manifest_id,
                document,
                hashlib.sha256(document.encode("utf-8")).hexdigest(),
            ),
        )

    def _validate_completed_hearing_model_call(
        self,
        connection: sqlite3.Connection,
        request: HearingModelRequest,
        response: HearingModelResponse,
        usage: HearingUsageReceipt,
    ) -> HearingModelCacheEntry:
        stored_response = self._load_hearing_model_response(
            connection,
            request.run_id,
            response.response_id,
        )
        if stored_response != response:
            raise HearingPersistenceConflict("completed hearing claim binds another response")
        entry = self._load_hearing_model_cache_entry(
            connection,
            request.run_id,
            request.cache_key,
        )
        if entry is None or entry != self._hearing_cache_entry(request, response):
            raise RepositoryIntegrityError("completed hearing claim has an invalid cache binding")
        usage_row = connection.execute(
            """
            SELECT * FROM m4_hearing_usage_receipts
            WHERE run_id = ? AND request_id = ?
            """,
            (request.run_id, request.request_id),
        ).fetchone()
        if usage_row is None or self._hearing_usage_receipt_from_row(usage_row) != usage:
            raise HearingPersistenceConflict("completed hearing claim binds another usage receipt")
        return entry

    @staticmethod
    def _validate_hearing_parse_binding(
        receipt: HearingModelParseReceipt,
        output: HearingRoleOutput | None,
    ) -> None:
        if receipt.status == ModelParseStatus.PARSED:
            if (
                output is None
                or receipt.parsed_payload_sha256 != output.payload.payload_sha256
                or output.parse_receipt_ref.artifact_id != receipt.parse_receipt_id
            ):
                raise ContractViolation("parsed hearing receipt requires its exact role output")
        elif output is not None:
            raise ContractViolation("failed hearing parse cannot publish a role output")

    @staticmethod
    def _validate_hearing_parse_call_scope(
        request: HearingModelRequest,
        response: HearingModelResponse,
        receipt: HearingModelParseReceipt,
    ) -> None:
        if (
            response.request_id != request.request_id
            or receipt.run_id != request.run_id
            or receipt.case_id != request.case_id
            or receipt.hearing_session_id != request.hearing_session_id
            or receipt.round_index != request.round_index
            or receipt.role != request.role
            or receipt.attempt_index != request.attempt_index
            or receipt.request_id != request.request_id
            or receipt.request_sha256 != request.request_sha256
            or receipt.response_id != response.response_id
            or receipt.response_content_sha256 != response.content_sha256
            or receipt.output_schema_sha256 != request.prompt_manifest.output_schema_sha256
            or receipt.manifest_id != request.manifest_id
        ):
            raise ContractViolation("hearing parse receipt conflicts with its exact completed call")

    def _validate_hearing_role_output_scope(
        self,
        connection: sqlite3.Connection,
        request: HearingModelRequest,
        response: HearingModelResponse,
        receipt: HearingModelParseReceipt,
        output: HearingRoleOutput,
    ) -> None:
        if (
            output.run_id != request.run_id
            or output.case_id != request.case_id
            or output.hearing_session_id != request.hearing_session_id
            or output.round_index != request.round_index
            or output.prior_acquisition_rounds != request.prior_acquisition_rounds
            or output.prior_rework_rounds != request.prior_rework_rounds
            or output.current_evidence_pack_id != request.current_evidence_pack_id
            or output.current_evidence_pack_version != request.current_evidence_pack_version
            or output.prompt_manifest != request.prompt_manifest
            or output.model_manifest_id != request.model_manifest_id
            or output.request_ref.artifact_id != request.request_id
            or output.response_ref.artifact_id != response.response_id
            or output.parse_receipt_ref.artifact_id != receipt.parse_receipt_id
            or output.role != request.role
            or output.precedent_retrieval_degraded != request.precedent_retrieval_degraded
            or output.precedent_retrieval_receipt_id != request.precedent_retrieval_receipt_id
            or output.precedent_retrieval_receipt_sha256
            != request.precedent_retrieval_receipt_sha256
            or output.initial_trigger_review_ref != request.initial_trigger_review_ref
            or output.initial_defect_codes != request.initial_defect_codes
            or output.rework_review_ref != request.rework_review_ref
            or output.rework_defect_codes != request.rework_defect_codes
            or output.manifest_id != request.manifest_id
        ):
            raise ContractViolation(
                "hearing role output conflicts with its request/response/parse closure"
            )
        expected_prosecutor = (
            request.prosecutor_output_ref.artifact_id
            if request.prosecutor_output_ref is not None
            else None
        )
        expected_defender = (
            request.defender_output_ref.artifact_id
            if request.defender_output_ref is not None
            else None
        )
        if (
            output.prosecutor_output_id != expected_prosecutor
            or output.defender_output_id != expected_defender
        ):
            raise ContractViolation(
                "hearing role output changed its ordered upstream role bindings"
            )
        existing = connection.execute(
            """
            SELECT parsed_output_id FROM m4_parsed_hearing_outputs
            WHERE run_id = ? AND cycle_scope_id = ? AND role = ?
            """,
            (request.run_id, request.cycle_scope_id, request.role.value),
        ).fetchone()
        if existing is not None and _row_str(existing, "parsed_output_id") != output.output_id:
            raise HearingPersistenceConflict("hearing cycle role already has another parsed output")

    @staticmethod
    def _hearing_payload_kind(output: HearingRoleOutput) -> str:
        if output.role == VlmRole.PROSECUTOR:
            return "PROSECUTION"
        if output.role == VlmRole.DEFENDER:
            return "DEFENSE"
        outcome = getattr(output.payload, "outcome", None)
        return (
            "JUDGE_ACQUISITION"
            if getattr(outcome, "outcome_type", None) == "ACQUISITION"
            else "JUDGE_VERDICT"
        )

    def _insert_hearing_role_output(
        self,
        connection: sqlite3.Connection,
        request: HearingModelRequest,
        output: HearingRoleOutput,
    ) -> None:
        document = _contract_document(output)
        connection.execute(
            """
            INSERT INTO m4_parsed_hearing_outputs(
                run_id, parsed_output_id, hearing_id,
                cycle_scope_id, cycle_scope_sha256, case_id,
                prior_acquisition_rounds, prior_rework_rounds,
                current_pack_id, current_pack_version,
                role, payload_kind, request_id, response_id, parse_receipt_id,
                response_content_sha256, output_schema_sha256,
                prompt_manifest_id, model_manifest_id,
                prosecutor_output_id, defender_output_id,
                precedent_retrieval_degraded,
                precedent_retrieval_receipt_id,
                precedent_retrieval_receipt_sha256,
                initial_trigger_review_id, initial_defect_codes_json,
                rework_review_id, rework_defect_codes_json,
                payload_sha256, manifest_id, output_json, document_sha256
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            (
                output.run_id,
                output.output_id,
                output.hearing_session_id,
                request.cycle_scope_id,
                request.cycle_scope_sha256,
                output.case_id,
                output.prior_acquisition_rounds,
                output.prior_rework_rounds,
                output.current_evidence_pack_id,
                output.current_evidence_pack_version,
                output.role.value,
                self._hearing_payload_kind(output),
                output.request_ref.artifact_id,
                output.response_ref.artifact_id,
                output.parse_receipt_ref.artifact_id,
                self._load_response_content_sha256(
                    connection,
                    output.run_id,
                    output.response_ref.artifact_id,
                ),
                output.prompt_manifest.output_schema_sha256,
                output.prompt_manifest.prompt_manifest_id,
                output.model_manifest_id,
                output.prosecutor_output_id,
                output.defender_output_id,
                int(output.precedent_retrieval_degraded),
                output.precedent_retrieval_receipt_id,
                output.precedent_retrieval_receipt_sha256,
                (
                    output.initial_trigger_review_ref.artifact_id
                    if output.initial_trigger_review_ref is not None
                    else None
                ),
                canonical_json([code.value for code in output.initial_defect_codes]),
                (
                    output.rework_review_ref.artifact_id
                    if output.rework_review_ref is not None
                    else None
                ),
                canonical_json([code.value for code in output.rework_defect_codes]),
                output.payload.payload_sha256,
                output.manifest_id,
                document,
                hashlib.sha256(document.encode("utf-8")).hexdigest(),
            ),
        )

    @staticmethod
    def _load_response_content_sha256(
        connection: sqlite3.Connection,
        run_id: str,
        response_id: str,
    ) -> str:
        row = connection.execute(
            """
            SELECT content_sha256 FROM m4_model_responses
            WHERE run_id = ? AND response_id = ?
            """,
            (run_id, response_id),
        ).fetchone()
        if row is None:
            raise EvidenceMissing("hearing model response authority is absent")
        return _row_str(row, "content_sha256")

    @staticmethod
    def _insert_hearing_parse_receipt(
        connection: sqlite3.Connection,
        receipt: HearingModelParseReceipt,
        output: HearingRoleOutput | None,
    ) -> None:
        document = _contract_document(receipt)
        cycle = connection.execute(
            """
            SELECT cycle_id, cycle_sha256 FROM m4_hearing_cycles
            WHERE run_id = ? AND hearing_id = ? AND cycle_index = ?
            """,
            (receipt.run_id, receipt.hearing_session_id, receipt.round_index),
        ).fetchone()
        if cycle is None:
            raise EvidenceMissing("hearing parse cycle authority is absent")
        connection.execute(
            """
            INSERT INTO m4_model_parse_receipts(
                run_id, parse_receipt_id, hearing_id,
                cycle_scope_id, cycle_scope_sha256, case_id, role,
                request_id, request_sha256, response_id, response_content_sha256,
                attempt_index, parser_version, output_schema_sha256,
                status, defects_json, parsed_output_id, repair_request_id,
                manifest_id, receipt_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                receipt.run_id,
                receipt.parse_receipt_id,
                receipt.hearing_session_id,
                _row_str(cycle, "cycle_id"),
                _row_str(cycle, "cycle_sha256"),
                receipt.case_id,
                receipt.role.value,
                receipt.request_id,
                receipt.request_sha256,
                receipt.response_id,
                receipt.response_content_sha256,
                receipt.attempt_index,
                receipt.parser_version,
                receipt.output_schema_sha256,
                receipt.status.value,
                canonical_json([item.model_dump(mode="json") for item in receipt.defects]),
                output.output_id if output is not None else None,
                receipt.repair_request_id,
                receipt.manifest_id,
                document,
                hashlib.sha256(document.encode("utf-8")).hexdigest(),
            ),
        )

    def _load_hearing_model_request(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        request_id: str,
    ) -> HearingModelRequest:
        row = connection.execute(
            """
            SELECT * FROM m4_model_call_claims
            WHERE run_id = ? AND request_id = ?
            """,
            (run_id, request_id),
        ).fetchone()
        if row is None:
            raise EvidenceMissing("hearing model request authority is absent")
        return self._hearing_model_request_from_claim_row(row)

    @staticmethod
    def _hearing_model_response_from_row(row: sqlite3.Row) -> HearingModelResponse:
        raw = _row_str(row, "response_json")
        try:
            response = HearingModelResponse.model_validate_json(raw)
        except ValidationError as exc:
            raise RepositoryIntegrityError("stored hearing model response is invalid") from exc
        _verify_contract_document(raw, response)
        indexed = (
            response.run_id == _row_str(row, "run_id"),
            response.response_id == _row_str(row, "response_id"),
            response.request_id == _row_str(row, "request_id"),
            response.request_sha256 == _row_str(row, "request_sha256"),
            response.cache_key == _row_str(row, "cache_key"),
            response.hearing_session_id == _row_str(row, "hearing_id"),
            response.case_id == _row_str(row, "case_id"),
            response.role.value == _row_str(row, "role"),
            response.attempt_index == _row_int(row, "attempt_index"),
            response.raw_response_ref == _row_str(row, "raw_response_ref"),
            response.content_sha256 == _row_str(row, "content_sha256"),
            response.size_bytes == _row_int(row, "size_bytes"),
            response.model_manifest_id == _row_str(row, "model_manifest_id"),
            response.manifest_id == _row_str(row, "manifest_id"),
            hashlib.sha256(raw.encode("utf-8")).hexdigest() == _row_str(row, "document_sha256"),
        )
        if not all(indexed):
            raise RepositoryIntegrityError(
                "hearing model response indexes conflict with its document"
            )
        return response

    def _load_hearing_model_response(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        response_id: str,
    ) -> HearingModelResponse:
        row = connection.execute(
            """
            SELECT * FROM m4_model_responses
            WHERE run_id = ? AND response_id = ?
            """,
            (run_id, response_id),
        ).fetchone()
        if row is None:
            raise EvidenceMissing("hearing model response authority is absent")
        response = self._hearing_model_response_from_row(row)
        request = self._load_hearing_model_request(connection, run_id, response.request_id)
        if (
            request.cycle_scope_id != _row_str(row, "cycle_scope_id")
            or request.cycle_scope_sha256 != _row_str(row, "cycle_scope_sha256")
            or self._hearing_model_call_purpose(request) != _row_str(row, "purpose")
        ):
            raise RepositoryIntegrityError(
                "hearing response cycle indexes conflict with its request"
            )
        return response

    @staticmethod
    def _hearing_cache_entry_from_row(row: sqlite3.Row) -> HearingModelCacheEntry:
        raw = _row_str(row, "entry_json")
        request_raw = _row_str(row, "request_json")
        try:
            entry = HearingModelCacheEntry.model_validate_json(raw)
            request = HearingModelRequest.model_validate_json(request_raw)
        except ValidationError as exc:
            raise RepositoryIntegrityError("stored hearing cache binding is invalid") from exc
        _verify_contract_document(raw, entry)
        _verify_contract_document(request_raw, request)
        if (
            entry.cache_key != _row_str(row, "cache_key")
            or entry.cache_entry_id != _row_str(row, "cache_entry_id")
            or entry.request_id != _row_str(row, "request_id")
            or entry.response_id != _row_str(row, "response_id")
            or entry.hearing_session_id != _row_str(row, "hearing_id")
            or request.request_id != entry.request_id
            or request.cache_key != entry.cache_key
            or hashlib.sha256(raw.encode("utf-8")).hexdigest() != _row_str(row, "document_sha256")
            or hashlib.sha256(request_raw.encode("utf-8")).hexdigest()
            != _row_str(row, "request_document_sha256")
        ):
            raise RepositoryIntegrityError(
                "hearing cache indexes conflict with canonical documents"
            )
        return entry

    def _load_hearing_model_cache_entry(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        cache_key: str,
    ) -> HearingModelCacheEntry | None:
        row = connection.execute(
            "SELECT * FROM m4_model_cache WHERE run_id = ? AND cache_key = ?",
            (run_id, cache_key),
        ).fetchone()
        if row is None:
            return None
        return self._hearing_cache_entry_from_row(row)

    @staticmethod
    def _hearing_parse_receipt_from_row(row: sqlite3.Row) -> HearingModelParseReceipt:
        raw = _row_str(row, "receipt_json")
        try:
            receipt = HearingModelParseReceipt.model_validate_json(raw)
        except ValidationError as exc:
            raise RepositoryIntegrityError("stored hearing parse receipt is invalid") from exc
        _verify_contract_document(raw, receipt)
        parsed_output_id = row["parsed_output_id"]
        if (
            receipt.parse_receipt_id != _row_str(row, "parse_receipt_id")
            or receipt.run_id != _row_str(row, "run_id")
            or receipt.hearing_session_id != _row_str(row, "hearing_id")
            or receipt.case_id != _row_str(row, "case_id")
            or receipt.role.value != _row_str(row, "role")
            or receipt.request_id != _row_str(row, "request_id")
            or receipt.response_id != _row_str(row, "response_id")
            or receipt.status.value != _row_str(row, "status")
            or (receipt.parsed_payload_sha256 is not None and parsed_output_id is None)
            or hashlib.sha256(raw.encode("utf-8")).hexdigest() != _row_str(row, "document_sha256")
        ):
            raise RepositoryIntegrityError(
                "hearing parse receipt indexes conflict with its document"
            )
        return receipt

    @staticmethod
    def _hearing_role_output_from_row(
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> HearingRoleOutput:
        raw = _row_str(row, "output_json")
        try:
            output = HearingRoleOutput.model_validate_json(raw)
        except ValidationError as exc:
            raise RepositoryIntegrityError("stored hearing role output is invalid") from exc
        _verify_contract_document(raw, output)
        cycle = connection.execute(
            """
            SELECT * FROM m4_hearing_cycles
            WHERE run_id = ? AND cycle_id = ? AND cycle_sha256 = ?
            """,
            (
                output.run_id,
                _row_str(row, "cycle_scope_id"),
                _row_str(row, "cycle_scope_sha256"),
            ),
        ).fetchone()
        if (
            cycle is None
            or output.output_id != _row_str(row, "parsed_output_id")
            or output.run_id != _row_str(row, "run_id")
            or output.hearing_session_id != _row_str(row, "hearing_id")
            or output.case_id != _row_str(row, "case_id")
            or output.round_index != _row_int(cycle, "cycle_index")
            or output.prior_acquisition_rounds != _row_int(cycle, "prior_acquisition_rounds")
            or output.prior_rework_rounds != _row_int(cycle, "prior_rework_rounds")
            or output.current_evidence_pack_id != _row_str(cycle, "cycle_pack_id")
            or output.current_evidence_pack_version != _row_int(cycle, "cycle_pack_version")
            or output.role.value != _row_str(row, "role")
            or output.request_ref.artifact_id != _row_str(row, "request_id")
            or output.response_ref.artifact_id != _row_str(row, "response_id")
            or output.parse_receipt_ref.artifact_id != _row_str(row, "parse_receipt_id")
            or output.payload.payload_sha256 != _row_str(row, "payload_sha256")
            or output.manifest_id != _row_str(row, "manifest_id")
            or hashlib.sha256(raw.encode("utf-8")).hexdigest() != _row_str(row, "document_sha256")
        ):
            raise RepositoryIntegrityError("hearing role output indexes conflict with its document")
        return output

    def _load_hearing_role_output(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        output_id: str,
    ) -> HearingRoleOutput:
        row = connection.execute(
            """
            SELECT * FROM m4_parsed_hearing_outputs
            WHERE run_id = ? AND parsed_output_id = ?
            """,
            (run_id, output_id),
        ).fetchone()
        if row is None:
            raise EvidenceMissing("hearing role output authority is absent")
        return self._hearing_role_output_from_row(connection, row)

    @staticmethod
    def _hearing_usage_receipt_from_row(row: sqlite3.Row) -> HearingUsageReceipt:
        raw = _row_str(row, "usage_json")
        try:
            usage = HearingUsageReceipt.model_validate_json(raw)
        except ValidationError as exc:
            raise RepositoryIntegrityError("stored hearing usage receipt is invalid") from exc
        _verify_contract_document(raw, usage)
        if (
            usage.usage_receipt_id != _row_str(row, "usage_receipt_id")
            or usage.run_id != _row_str(row, "run_id")
            or usage.hearing_session_id != _row_str(row, "hearing_id")
            or usage.case_id != _row_str(row, "case_id")
            or usage.role.value != _row_str(row, "role")
            or usage.request_ref.artifact_id != _row_str(row, "request_id")
            or usage.response_ref.artifact_id != _row_str(row, "response_id")
            or usage.input_images != _row_int(row, "input_images")
            or usage.input_pixels != _row_int(row, "input_pixels")
            or usage.output_tokens != _row_int(row, "output_tokens")
            or usage.manifest_id != _row_str(row, "manifest_id")
            or hashlib.sha256(raw.encode("utf-8")).hexdigest() != _row_str(row, "document_sha256")
        ):
            raise RepositoryIntegrityError(
                "hearing usage receipt indexes conflict with its document"
            )
        return usage

    def load_hearing_model_request(
        self,
        run_id: str,
        request_id: str,
    ) -> HearingModelRequest:
        require_reference_token(run_id, "hearing repository run_id")
        require_reference_token(request_id, "hearing request ID")
        connection = self._host._connection(require_hardening=True, require_m4=True)
        try:
            return self._load_hearing_model_request(connection, run_id, request_id)
        finally:
            connection.close()

    def load_hearing_model_response(
        self,
        run_id: str,
        response_id: str,
    ) -> HearingModelResponse:
        require_reference_token(run_id, "hearing repository run_id")
        require_reference_token(response_id, "hearing response ID")
        connection = self._host._connection(require_hardening=True, require_m4=True)
        try:
            return self._load_hearing_model_response(connection, run_id, response_id)
        finally:
            connection.close()

    def load_hearing_model_cache_entry(
        self,
        run_id: str,
        cache_key: str,
    ) -> HearingModelCacheEntry | None:
        require_reference_token(run_id, "hearing repository run_id")
        require_reference_token(cache_key, "hearing cache key")
        connection = self._host._connection(require_hardening=True, require_m4=True)
        try:
            return self._load_hearing_model_cache_entry(connection, run_id, cache_key)
        finally:
            connection.close()

    def load_hearing_parse_receipt(
        self,
        run_id: str,
        parse_receipt_id: str,
    ) -> HearingModelParseReceipt:
        require_reference_token(run_id, "hearing repository run_id")
        require_reference_token(parse_receipt_id, "hearing parse receipt ID")
        connection = self._host._connection(require_hardening=True, require_m4=True)
        try:
            row = connection.execute(
                """
                SELECT * FROM m4_model_parse_receipts
                WHERE run_id = ? AND parse_receipt_id = ?
                """,
                (run_id, parse_receipt_id),
            ).fetchone()
            if row is None:
                raise EvidenceMissing("hearing parse receipt authority is absent")
            return self._hearing_parse_receipt_from_row(row)
        finally:
            connection.close()

    def load_hearing_role_output(
        self,
        run_id: str,
        output_id: str,
    ) -> HearingRoleOutput:
        require_reference_token(run_id, "hearing repository run_id")
        require_reference_token(output_id, "hearing role output ID")
        connection = self._host._connection(require_hardening=True, require_m4=True)
        try:
            return self._load_hearing_role_output(connection, run_id, output_id)
        finally:
            connection.close()

    def load_hearing_usage_receipt(
        self,
        run_id: str,
        usage_receipt_id: str,
    ) -> HearingUsageReceipt:
        require_reference_token(run_id, "hearing repository run_id")
        require_reference_token(usage_receipt_id, "hearing usage receipt ID")
        connection = self._host._connection(require_hardening=True, require_m4=True)
        try:
            row = connection.execute(
                """
                SELECT * FROM m4_hearing_usage_receipts
                WHERE run_id = ? AND usage_receipt_id = ?
                """,
                (run_id, usage_receipt_id),
            ).fetchone()
            if row is None:
                raise EvidenceMissing("hearing usage receipt authority is absent")
            return self._hearing_usage_receipt_from_row(row)
        finally:
            connection.close()

    def complete_hearing_round(
        self,
        run_id: str,
        hearing_round: HearingRound,
    ) -> None:
        """Validate the complete persisted trace and append one frozen round."""

        require_reference_token(run_id, "hearing repository run_id")
        validated = HearingRound.model_validate(hearing_round.model_dump(mode="json"))
        if validated.run_id != run_id:
            raise ContractViolation("hearing round belongs to another run")
        try:
            with self._host._immediate(require_m4=True) as connection:
                scope = self._load_hearing_cycle(
                    connection,
                    run_id,
                    validated.cycle_scope_id,
                )
                validate_hearing_cycle_scope_binding(scope, validated)
                existing = connection.execute(
                    """
                    SELECT round_id
                    FROM m4_hearing_rounds
                    WHERE run_id = ? AND (round_id = ? OR cycle_scope_id = ?)
                    """,
                    (run_id, validated.round_id, validated.cycle_scope_id),
                ).fetchone()
                if existing is not None:
                    stored = self._load_hearing_round(
                        connection,
                        run_id,
                        _row_str(existing, "round_id"),
                    )
                    if stored != validated:
                        raise HearingPersistenceConflict(
                            "hearing round scope conflicts with persisted content"
                        )
                    return
                self._validate_complete_hearing_record(connection, validated)
                self._insert_hearing_round(connection, validated)
                self._host._fault("hearing.round.before_commit")
        except sqlite3.IntegrityError as exc:
            raise ContractViolation("hearing round authority was rejected") from exc

    def commit_hearing_verdict_review(
        self,
        run_id: str,
        expected_case_revision: int,
        expected_audit_head: AuditHead,
        verdict: Verdict,
        binding: HearingVerdictBinding,
        review: ProceduralReview,
        checkpoint: HearingCheckpoint,
    ) -> HearingVerdictReviewResult:
        """Atomically bind one terminal Judge round, L5 review, checkpoint, and Case."""

        require_reference_token(run_id, "hearing repository run_id")
        self._require_expected_case_revision(expected_case_revision)
        validated_verdict = Verdict.model_validate(verdict.model_dump(mode="json"))
        validated_binding = HearingVerdictBinding.model_validate(binding.model_dump(mode="json"))
        validated_review = ProceduralReview.model_validate(review.model_dump(mode="json"))
        validated_checkpoint = HearingCheckpoint.model_validate(checkpoint.model_dump(mode="json"))
        self._validate_verdict_review_documents(
            run_id=run_id,
            verdict=validated_verdict,
            binding=validated_binding,
            review=validated_review,
            checkpoint=validated_checkpoint,
        )

        try:
            with self._host._immediate(require_m4=True) as connection:
                existing = connection.execute(
                    """
                    SELECT 1 FROM m4_hearing_verdict_bindings
                    WHERE run_id = ? AND binding_id = ?
                    """,
                    (run_id, validated_binding.binding_id),
                ).fetchone()
                if existing is not None:
                    return self._replay_verdict_review(
                        connection,
                        run_id=run_id,
                        expected_case_revision=expected_case_revision,
                        expected_audit_head=expected_audit_head,
                        verdict=validated_verdict,
                        binding=validated_binding,
                        review=validated_review,
                        checkpoint=validated_checkpoint,
                    )

                loaded = self._host._load_case(connection, run_id, validated_binding.case_id)
                if loaded.snapshot.revision != expected_case_revision:
                    raise ConcurrentModification(
                        "case revision changed before hearing verdict commit"
                    )
                head = self._host._validated_head(connection, run_id)
                self._require_expected_head(head, expected_audit_head)
                self._validate_new_verdict_review_authority(
                    connection,
                    case=loaded.snapshot.case,
                    verdict=validated_verdict,
                    binding=validated_binding,
                    review=validated_review,
                    checkpoint=validated_checkpoint,
                )

                status = (
                    CaseStatus.READY_FOR_ALERT_POLICY
                    if validated_review.passed
                    else CaseStatus.REWORK_REQUIRED
                )
                new_case = self._case_with_updates(
                    loaded.snapshot.case,
                    status=status,
                    verdicts=(*loaded.snapshot.case.verdicts, validated_verdict),
                    procedural_reviews=(
                        *loaded.snapshot.case.procedural_reviews,
                        validated_review,
                    ),
                    timeline_entry=TimelineEntry(
                        sequence=len(loaded.snapshot.case.timeline),
                        action=AuditAction.CASE_STATE_CHANGED.value,
                        stage="PROCEDURAL_GATE",
                        object_ref=validated_review.review_id,
                        details={
                            "passed": validated_review.passed,
                            "verdict_id": validated_verdict.verdict_id,
                        },
                    ),
                )
                audit_sequence = head.sequence + 1
                self._insert_verdict_review_roots(
                    connection,
                    validated_verdict,
                    validated_review,
                    audit_sequence=audit_sequence,
                )
                self._host._fault("hearing.verdict.after_verdict_review")
                self._insert_hearing_verdict_binding(
                    connection,
                    validated_binding,
                    cycle_scope_id=validated_checkpoint.cycle_scope_id,
                    cycle_scope_sha256=validated_checkpoint.cycle_scope_sha256,
                )
                self._host._fault("hearing.verdict.after_binding")
                self._insert_hearing_checkpoint(connection, validated_checkpoint)
                self._host._fault("hearing.verdict.after_checkpoint")
                committed = self._commit_case_version(
                    connection,
                    previous=loaded.snapshot,
                    previous_document_sha256=loaded.document_sha256,
                    new_case=new_case,
                    expected_head=head,
                    object_ref=ArtifactRef(
                        kind=ArtifactKind.PROCEDURAL_REVIEW,
                        artifact_id=validated_review.review_id,
                    ),
                    fault_prefix="hearing.verdict",
                )
                self._host._fault("hearing.verdict.before_commit")
                return HearingVerdictReviewResult(
                    case=committed,
                    binding=validated_binding,
                    review=validated_review,
                    checkpoint=validated_checkpoint,
                    created=True,
                )
        except sqlite3.IntegrityError as exc:
            raise ContractViolation("hearing verdict transaction was rejected") from exc

    @staticmethod
    def _validate_verdict_review_documents(
        *,
        run_id: str,
        verdict: Verdict,
        binding: HearingVerdictBinding,
        review: ProceduralReview,
        checkpoint: HearingCheckpoint,
    ) -> None:
        expected_phase = (
            HearingCheckpointPhase.COMPLETE
            if review.passed
            else HearingCheckpointPhase.REWORK_READY
        )
        review_ref = checkpoint.procedural_review_ref
        if (
            verdict.run_id != run_id
            or binding.run_id != run_id
            or review.run_id != run_id
            or checkpoint.run_id != run_id
            or binding.case_id != verdict.case_id
            or review.case_id != verdict.case_id
            or checkpoint.case_id != verdict.case_id
            or binding.verdict_id != verdict.verdict_id
            or binding.verdict_version != verdict.version
            or binding.verdict_input_sha256 != verdict.verdict_input_sha256
            or binding.verdict_sha256 != verdict.verdict_sha256
            or binding.evidence_pack_id != verdict.evidence_pack_id
            or binding.evidence_pack_version != verdict.evidence_pack_version
            or review.evidence_pack_id != verdict.evidence_pack_id
            or review.evidence_pack_version != verdict.evidence_pack_version
            or review.reviewed_verdict_id != verdict.verdict_id
            or review.reviewed_verdict_version != verdict.version
            or review.reviewed_verdict_sha256 != verdict.verdict_sha256
            or checkpoint.hearing_session_id != binding.hearing_session_id
            or checkpoint.current_evidence_pack_id != verdict.evidence_pack_id
            or checkpoint.current_evidence_pack_version != verdict.evidence_pack_version
            or checkpoint.phase != expected_phase
            or review_ref is None
            or review_ref.kind != ArtifactKind.PROCEDURAL_REVIEW
            or review_ref.artifact_id != review.review_id
            or len(
                {
                    verdict.manifest_id,
                    binding.manifest_id,
                    review.manifest_id,
                    checkpoint.manifest_id,
                }
            )
            != 1
        ):
            raise ContractViolation(
                "verdict, hearing binding, review, and checkpoint do not share one authority"
            )

    def _validate_new_verdict_review_authority(
        self,
        connection: sqlite3.Connection,
        *,
        case: Case,
        verdict: Verdict,
        binding: HearingVerdictBinding,
        review: ProceduralReview,
        checkpoint: HearingCheckpoint,
    ) -> None:
        if (
            case.status != CaseStatus.DELIBERATING
            or case.run_id != verdict.run_id
            or case.case_id != verdict.case_id
            or case.manifest_id != verdict.manifest_id
            or not case.evidence_packs
            or case.evidence_packs[-1].pack_id != verdict.evidence_pack_id
            or case.evidence_packs[-1].version != verdict.evidence_pack_version
            or not case.screening_results
            or case.screening_results[-1].screening_id != verdict.screening_id
            or verdict.version != len(case.verdicts) + 1
            or review.version != len(case.procedural_reviews) + 1
        ):
            raise ConcurrentModification(
                "hearing verdict does not consume the latest DELIBERATING Case authority"
            )
        record = self._rebuild_hearing_record(
            connection,
            run_id=verdict.run_id,
            case_id=verdict.case_id,
            hearing_id=binding.hearing_session_id,
        )
        last_round = record.rounds[-1]
        judge_payload = last_round.judge_output.payload
        if not isinstance(judge_payload, JudgeModelPayload) or not isinstance(
            judge_payload.outcome,
            JudgeFinalDecisionPayload,
        ):
            raise ContractViolation("only a terminal Judge round may produce a Verdict")
        final = judge_payload.outcome
        if (
            binding.hearing_record_id != record.record_id
            or binding.hearing_record_version != record.version
            or binding.hearing_record_sha256 != record.record_sha256
            or binding.judge_round_id != last_round.round_id
            or binding.judge_round_index != last_round.round_index
            or binding.evidence_pack_id != record.current_evidence_pack_id
            or binding.evidence_pack_version != record.current_evidence_pack_version
            or binding.prosecutor_output_id != last_round.prosecutor_output.output_id
            or binding.defender_output_id != last_round.defender_output.output_id
            or binding.judge_output_id != last_round.judge_output.output_id
            or binding.model_request_refs != record.model_request_refs
            or binding.model_response_refs != record.model_response_refs
            or binding.parse_receipt_refs != record.parse_receipt_refs
            or verdict.model_response_refs != record.model_response_refs
            or verdict.screening_id != record.screening_id
            or verdict.decision != final.decision
            or verdict.confidence != final.confidence
            or verdict.recommended_alert_level != final.recommended_alert_level
            or verdict.rationale_summary != final.rationale_summary
            or verdict.evidence_citations != final.evidence_citations
            or verdict.objective_claims != final.objective_claims
            or verdict.observation_sufficiency != final.observation_sufficiency
        ):
            raise ContractViolation(
                "proposed Verdict differs from its reconstructed hearing record"
            )
        previous = self._load_latest_hearing_checkpoint(
            connection,
            verdict.run_id,
            binding.hearing_session_id,
        )
        if (
            previous.phase != HearingCheckpointPhase.ROUND_COMPLETE
            or previous.judge_output is None
            or previous.judge_output.output_id != last_round.judge_output.output_id
            or checkpoint.version != previous.version + 1
            or checkpoint.previous_checkpoint_id != previous.checkpoint_id
            or checkpoint.previous_checkpoint_sha256 != previous.checkpoint_sha256
            or checkpoint.previous_phase != previous.phase
            or checkpoint.cycle_scope_id != last_round.cycle_scope_id
            or checkpoint.cycle_scope_sha256 != last_round.cycle_scope_sha256
        ):
            raise ConcurrentModification(
                "hearing verdict checkpoint does not advance the exact completed round"
            )
        scope = self._load_hearing_cycle(connection, verdict.run_id, checkpoint.cycle_scope_id)
        try:
            validate_hearing_cycle_scope_binding(scope, checkpoint)
        except (TypeError, ValueError) as exc:
            raise ContractViolation("verdict checkpoint conflicts with its cycle") from exc

    def _replay_verdict_review(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        expected_case_revision: int,
        expected_audit_head: AuditHead,
        verdict: Verdict,
        binding: HearingVerdictBinding,
        review: ProceduralReview,
        checkpoint: HearingCheckpoint,
    ) -> HearingVerdictReviewResult:
        if (
            self._load_hearing_verdict_binding(connection, run_id, binding.binding_id) != binding
            or self._load_verdict(connection, run_id, verdict.verdict_id) != verdict
            or self._load_procedural_review(connection, run_id, review.review_id) != review
            or self._load_hearing_checkpoint(connection, run_id, checkpoint.checkpoint_id)
            != checkpoint
        ):
            raise HearingPersistenceConflict(
                "hearing verdict identity conflicts with persisted content"
            )
        committed = self._load_case_revision(
            connection,
            run_id,
            verdict.case_id,
            expected_case_revision + 1,
        )
        expected_status = (
            CaseStatus.READY_FOR_ALERT_POLICY if review.passed else CaseStatus.REWORK_REQUIRED
        )
        if (
            committed.case.status != expected_status
            or not committed.case.verdicts
            or committed.case.verdicts[-1] != verdict
            or not committed.case.procedural_reviews
            or committed.case.procedural_reviews[-1] != review
        ):
            raise RepositoryIntegrityError(
                "persisted hearing verdict roots lack their exact Case transition"
            )
        self._verify_transition_audit(
            connection,
            run_id=run_id,
            audit_sequence=expected_audit_head.sequence + 1,
            expected_head=expected_audit_head,
            object_id=review.review_id,
            object_kind=ArtifactKind.PROCEDURAL_REVIEW,
        )
        return HearingVerdictReviewResult(
            case=committed,
            binding=binding,
            review=review,
            checkpoint=checkpoint,
            created=False,
        )

    def begin_hearing_rework(
        self,
        run_id: str,
        expected_case_revision: int,
        expected_audit_head: AuditHead,
        receipt: HearingReworkReceipt,
        cycle_scope: HearingCycleScope,
        checkpoint: HearingCheckpoint,
    ) -> HearingReworkResult:
        """Atomically open the adjacent cycle authorized by one failed hearing review."""

        require_reference_token(run_id, "hearing repository run_id")
        self._require_expected_case_revision(expected_case_revision)
        validated_receipt = HearingReworkReceipt.model_validate(receipt.model_dump(mode="json"))
        validated_cycle = HearingCycleScope.model_validate(cycle_scope.model_dump(mode="json"))
        validated_checkpoint = HearingCheckpoint.model_validate(checkpoint.model_dump(mode="json"))
        self._validate_rework_documents(
            run_id=run_id,
            receipt=validated_receipt,
            cycle=validated_cycle,
            checkpoint=validated_checkpoint,
        )

        try:
            with self._host._immediate(require_m4=True) as connection:
                existing = connection.execute(
                    """
                    SELECT 1 FROM m4_rework_receipts
                    WHERE run_id = ? AND rework_receipt_id = ?
                    """,
                    (run_id, validated_receipt.receipt_id),
                ).fetchone()
                if existing is not None:
                    return self._replay_hearing_rework(
                        connection,
                        run_id=run_id,
                        expected_case_revision=expected_case_revision,
                        expected_audit_head=expected_audit_head,
                        receipt=validated_receipt,
                        cycle=validated_cycle,
                        checkpoint=validated_checkpoint,
                    )

                loaded = self._host._load_case(connection, run_id, validated_receipt.case_id)
                if loaded.snapshot.revision != expected_case_revision:
                    raise ConcurrentModification("case revision changed before hearing rework")
                head = self._host._validated_head(connection, run_id)
                self._require_expected_head(head, expected_audit_head)
                self._validate_new_rework_authority(
                    connection,
                    case=loaded.snapshot.case,
                    receipt=validated_receipt,
                    cycle=validated_cycle,
                    checkpoint=validated_checkpoint,
                )
                failed_review = loaded.snapshot.case.procedural_reviews[-1]
                new_case = self._case_with_updates(
                    loaded.snapshot.case,
                    status=CaseStatus.DELIBERATING,
                    timeline_entry=TimelineEntry(
                        sequence=len(loaded.snapshot.case.timeline),
                        action=AuditAction.CASE_STATE_CHANGED.value,
                        stage="HEARING",
                        object_ref=validated_receipt.receipt_id,
                        details={
                            "rework_index": validated_receipt.rework_index,
                            "status": CaseStatus.DELIBERATING.value,
                        },
                    ),
                )
                self._insert_hearing_cycle(connection, validated_cycle)
                self._host._fault("hearing.rework.after_cycle")
                self._insert_hearing_rework_receipt(connection, validated_receipt)
                self._host._fault("hearing.rework.after_receipt")
                self._insert_hearing_checkpoint(connection, validated_checkpoint)
                self._host._fault("hearing.rework.after_checkpoint")
                committed = self._commit_case_version(
                    connection,
                    previous=loaded.snapshot,
                    previous_document_sha256=loaded.document_sha256,
                    new_case=new_case,
                    expected_head=head,
                    object_ref=ArtifactRef(
                        kind=ArtifactKind.PROCEDURAL_REVIEW,
                        artifact_id=failed_review.review_id,
                    ),
                    fault_prefix="hearing.rework",
                )
                self._host._fault("hearing.rework.before_commit")
                return HearingReworkResult(
                    case=committed,
                    receipt=validated_receipt,
                    cycle=validated_cycle,
                    checkpoint=validated_checkpoint,
                    created=True,
                )
        except sqlite3.IntegrityError as exc:
            raise ContractViolation("hearing rework transaction was rejected") from exc

    @staticmethod
    def _validate_rework_documents(
        *,
        run_id: str,
        receipt: HearingReworkReceipt,
        cycle: HearingCycleScope,
        checkpoint: HearingCheckpoint,
    ) -> None:
        rework_ref = cycle.rework_review_ref
        if (
            receipt.run_id != run_id
            or cycle.run_id != run_id
            or checkpoint.run_id != run_id
            or cycle.case_id != receipt.case_id
            or checkpoint.case_id != receipt.case_id
            or cycle.hearing_session_id != receipt.hearing_session_id
            or checkpoint.hearing_session_id != receipt.hearing_session_id
            or receipt.next_cycle_scope_id != cycle.cycle_id
            or receipt.next_cycle_scope_sha256 != cycle.cycle_sha256
            or cycle.prior_rework_rounds != receipt.rework_index
            or rework_ref is None
            or rework_ref.kind != ArtifactKind.PROCEDURAL_REVIEW
            or rework_ref.artifact_id != receipt.failed_review_id
            or cycle.rework_defect_codes != receipt.defect_codes
            or checkpoint.phase != HearingCheckpointPhase.PRECEDENT_RETRIEVAL_PENDING
            or checkpoint.version <= 1
            or len({receipt.manifest_id, cycle.manifest_id, checkpoint.manifest_id}) != 1
        ):
            raise ContractViolation("rework receipt, cycle, and checkpoint authority conflict")
        try:
            validate_hearing_cycle_scope_binding(cycle, checkpoint)
        except (TypeError, ValueError) as exc:
            raise ContractViolation("rework checkpoint does not bind its new cycle") from exc

    def _validate_new_rework_authority(
        self,
        connection: sqlite3.Connection,
        *,
        case: Case,
        receipt: HearingReworkReceipt,
        cycle: HearingCycleScope,
        checkpoint: HearingCheckpoint,
    ) -> None:
        if (
            case.status != CaseStatus.REWORK_REQUIRED
            or case.run_id != receipt.run_id
            or case.case_id != receipt.case_id
            or case.manifest_id != receipt.manifest_id
            or not case.procedural_reviews
            or case.procedural_reviews[-1].passed
            or case.procedural_reviews[-1].review_id != receipt.failed_review_id
            or tuple(defect.code for defect in case.procedural_reviews[-1].defects)
            != receipt.defect_codes
        ):
            raise ConcurrentModification(
                "rework receipt does not consume the latest failed Case review"
            )
        session = self._load_hearing_session(
            connection,
            receipt.run_id,
            receipt.hearing_session_id,
        )
        record = self._rebuild_hearing_record(
            connection,
            run_id=receipt.run_id,
            case_id=receipt.case_id,
            hearing_id=receipt.hearing_session_id,
        )
        last_round = record.rounds[-1]
        previous = self._load_latest_hearing_checkpoint(
            connection,
            receipt.run_id,
            receipt.hearing_session_id,
        )
        if (
            receipt.rework_index > session.rework_round_limit
            or receipt.prior_round_id != last_round.round_id
            or last_round.prior_rework_rounds + 1 != receipt.rework_index
            or cycle.prior_acquisition_rounds != last_round.prior_acquisition_rounds
            or cycle.cycle_evidence_pack_id != last_round.resulting_evidence_pack_id
            or cycle.cycle_evidence_pack_version != last_round.resulting_evidence_pack_version
            or not case.evidence_packs
            or case.evidence_packs[-1].pack_id != cycle.cycle_evidence_pack_id
            or case.evidence_packs[-1].version != cycle.cycle_evidence_pack_version
            or previous.phase != HearingCheckpointPhase.REWORK_READY
            or previous.procedural_review_ref is None
            or previous.procedural_review_ref.artifact_id != receipt.failed_review_id
            or checkpoint.version != previous.version + 1
            or checkpoint.previous_checkpoint_id != previous.checkpoint_id
            or checkpoint.previous_checkpoint_sha256 != previous.checkpoint_sha256
            or checkpoint.previous_phase != previous.phase
        ):
            raise ConcurrentModification(
                "rework cycle does not advance the exact failed hearing round"
            )

    def _replay_hearing_rework(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        expected_case_revision: int,
        expected_audit_head: AuditHead,
        receipt: HearingReworkReceipt,
        cycle: HearingCycleScope,
        checkpoint: HearingCheckpoint,
    ) -> HearingReworkResult:
        if (
            self._load_hearing_rework_receipt(connection, run_id, receipt.receipt_id) != receipt
            or self._load_hearing_cycle(connection, run_id, cycle.cycle_id) != cycle
            or self._load_hearing_checkpoint(connection, run_id, checkpoint.checkpoint_id)
            != checkpoint
        ):
            raise HearingPersistenceConflict(
                "hearing rework identity conflicts with persisted content"
            )
        committed = self._load_case_revision(
            connection,
            run_id,
            receipt.case_id,
            expected_case_revision + 1,
        )
        if (
            committed.case.status != CaseStatus.DELIBERATING
            or not committed.case.timeline
            or committed.case.timeline[-1].object_ref != receipt.receipt_id
        ):
            raise RepositoryIntegrityError(
                "persisted hearing rework lacks its exact Case transition"
            )
        self._verify_transition_audit(
            connection,
            run_id=run_id,
            audit_sequence=expected_audit_head.sequence + 1,
            expected_head=expected_audit_head,
            object_id=receipt.failed_review_id,
            object_kind=ArtifactKind.PROCEDURAL_REVIEW,
        )
        return HearingReworkResult(
            case=committed,
            receipt=receipt,
            cycle=cycle,
            checkpoint=checkpoint,
            created=False,
        )

    def commit_hearing_human_review(
        self,
        run_id: str,
        expected_case_revision: int,
        expected_audit_head: AuditHead,
        receipt: HearingHumanReviewReceipt,
        checkpoint: HearingCheckpoint,
    ) -> HearingHumanReviewResult:
        """Atomically persist one typed M4 human transfer and Case transition."""

        require_reference_token(run_id, "hearing repository run_id")
        self._require_expected_case_revision(expected_case_revision)
        validated_receipt = HearingHumanReviewReceipt.model_validate(
            receipt.model_dump(mode="json")
        )
        validated_checkpoint = HearingCheckpoint.model_validate(checkpoint.model_dump(mode="json"))
        self._validate_human_review_documents(
            run_id=run_id,
            receipt=validated_receipt,
            checkpoint=validated_checkpoint,
        )

        try:
            with self._host._immediate(require_m4=True) as connection:
                existing = connection.execute(
                    """
                    SELECT 1 FROM m4_hearing_human_review_receipts
                    WHERE run_id = ? AND receipt_id = ?
                    """,
                    (run_id, validated_receipt.receipt_id),
                ).fetchone()
                if existing is not None:
                    return self._replay_hearing_human_review(
                        connection,
                        run_id=run_id,
                        expected_case_revision=expected_case_revision,
                        expected_audit_head=expected_audit_head,
                        receipt=validated_receipt,
                        checkpoint=validated_checkpoint,
                    )

                loaded = self._host._load_case(connection, run_id, validated_receipt.case_id)
                if loaded.snapshot.revision != expected_case_revision:
                    raise ConcurrentModification(
                        "case revision changed before hearing human review"
                    )
                head = self._host._validated_head(connection, run_id)
                self._require_expected_head(head, expected_audit_head)
                self._validate_new_human_review_authority(
                    connection,
                    case=loaded.snapshot.case,
                    receipt=validated_receipt,
                    checkpoint=validated_checkpoint,
                )
                new_case = self._case_with_updates(
                    loaded.snapshot.case,
                    status=CaseStatus.HUMAN_REVIEW,
                    current_backlog_item_id=None,
                    timeline_entry=TimelineEntry(
                        sequence=len(loaded.snapshot.case.timeline),
                        action=AuditAction.CASE_STATE_CHANGED.value,
                        stage="HEARING",
                        object_ref=validated_receipt.receipt_id,
                        details={
                            "reason": validated_receipt.reason.value,
                            "hearing_session_id": validated_receipt.hearing_session_id,
                            "judge_cycle": validated_receipt.judge_cycle,
                        },
                    ),
                )
                self._insert_hearing_human_review_receipt(connection, validated_receipt)
                self._host._fault("hearing.human_review.after_receipt")
                self._insert_hearing_checkpoint(connection, validated_checkpoint)
                self._host._fault("hearing.human_review.after_checkpoint")
                committed = self._commit_case_version(
                    connection,
                    previous=loaded.snapshot,
                    previous_document_sha256=loaded.document_sha256,
                    new_case=new_case,
                    expected_head=head,
                    object_ref=ArtifactRef(
                        kind=ArtifactKind.CASE,
                        artifact_id=validated_receipt.case_id,
                    ),
                    fault_prefix="hearing.human_review",
                )
                self._host._fault("hearing.human_review.before_commit")
                return HearingHumanReviewResult(
                    case=committed,
                    receipt=validated_receipt,
                    checkpoint=validated_checkpoint,
                    created=True,
                )
        except sqlite3.IntegrityError as exc:
            raise ContractViolation("hearing human-review transaction was rejected") from exc

    @staticmethod
    def _validate_human_review_documents(
        *,
        run_id: str,
        receipt: HearingHumanReviewReceipt,
        checkpoint: HearingCheckpoint,
    ) -> None:
        if (
            receipt.run_id != run_id
            or checkpoint.run_id != run_id
            or checkpoint.case_id != receipt.case_id
            or checkpoint.hearing_session_id != receipt.hearing_session_id
            or checkpoint.current_evidence_pack_id != receipt.current_evidence_pack_id
            or checkpoint.current_evidence_pack_version != receipt.current_evidence_pack_version
            or checkpoint.judge_cycle != receipt.judge_cycle
            or checkpoint.phase != HearingCheckpointPhase.HUMAN_REVIEW
            or checkpoint.human_review_receipt_id != receipt.receipt_id
            or checkpoint.human_review_receipt_sha256 != receipt.receipt_sha256
            or checkpoint.human_review_reason != receipt.reason
            or checkpoint.previous_checkpoint_id != receipt.source_checkpoint_id
            or checkpoint.previous_checkpoint_sha256 != receipt.source_checkpoint_sha256
            or checkpoint.version != receipt.source_checkpoint_version + 1
            or checkpoint.manifest_id != receipt.manifest_id
        ):
            raise ContractViolation(
                "human-review receipt and resulting checkpoint authority conflict"
            )

    def _validate_new_human_review_authority(
        self,
        connection: sqlite3.Connection,
        *,
        case: Case,
        receipt: HearingHumanReviewReceipt,
        checkpoint: HearingCheckpoint,
    ) -> None:
        expected_status = (
            CaseStatus.REWORK_REQUIRED
            if receipt.reason == HearingHumanReviewReason.REWORK_LIMIT_EXHAUSTED
            else CaseStatus.BACKLOGGED
            if receipt.reason == HearingHumanReviewReason.HEARING_BACKLOG_EXHAUSTED
            else CaseStatus.DELIBERATING
        )
        if (
            case.status != expected_status
            or case.run_id != receipt.run_id
            or case.case_id != receipt.case_id
            or case.manifest_id != receipt.manifest_id
            or not case.evidence_packs
            or case.evidence_packs[-1].pack_id != receipt.current_evidence_pack_id
            or case.evidence_packs[-1].version != receipt.current_evidence_pack_version
        ):
            raise ConcurrentModification(
                "human-review receipt does not consume the latest eligible Case"
            )
        previous = self._load_latest_hearing_checkpoint(
            connection,
            receipt.run_id,
            receipt.hearing_session_id,
        )
        if (
            previous.checkpoint_id != receipt.source_checkpoint_id
            or previous.checkpoint_sha256 != receipt.source_checkpoint_sha256
            or previous.version != receipt.source_checkpoint_version
            or checkpoint.previous_phase != previous.phase
            or receipt.current_evidence_pack_id != previous.current_evidence_pack_id
            or receipt.current_evidence_pack_version != previous.current_evidence_pack_version
            or receipt.judge_cycle != previous.judge_cycle
        ):
            raise ConcurrentModification("human-review receipt does not bind the latest checkpoint")
        if receipt.reason == HearingHumanReviewReason.REWORK_LIMIT_EXHAUSTED:
            review_ref = receipt.procedural_review_ref
            if (
                review_ref is None
                or not case.procedural_reviews
                or case.procedural_reviews[-1].passed
                or review_ref.artifact_id != case.procedural_reviews[-1].review_id
                or previous.phase != HearingCheckpointPhase.REWORK_READY
            ):
                raise ContractViolation(
                    "rework exhaustion lacks the latest failed review authority"
                )
        if receipt.reason == HearingHumanReviewReason.HEARING_BACKLOG_EXHAUSTED:
            backlog_ref = receipt.backlog_item_ref
            if backlog_ref is None or case.current_backlog_item_id != backlog_ref.artifact_id:
                raise ContractViolation("backlog exhaustion lacks the Case's exact backlog binding")
        scope = self._load_hearing_cycle(connection, receipt.run_id, checkpoint.cycle_scope_id)
        try:
            validate_hearing_cycle_scope_binding(scope, checkpoint)
        except (TypeError, ValueError) as exc:
            raise ContractViolation("human-review checkpoint conflicts with its cycle") from exc

    def _replay_hearing_human_review(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        expected_case_revision: int,
        expected_audit_head: AuditHead,
        receipt: HearingHumanReviewReceipt,
        checkpoint: HearingCheckpoint,
    ) -> HearingHumanReviewResult:
        if (
            self._load_hearing_human_review_receipt(connection, run_id, receipt.receipt_id)
            != receipt
            or self._load_hearing_checkpoint(connection, run_id, checkpoint.checkpoint_id)
            != checkpoint
        ):
            raise HearingPersistenceConflict(
                "hearing human-review identity conflicts with persisted content"
            )
        committed = self._load_case_revision(
            connection,
            run_id,
            receipt.case_id,
            expected_case_revision + 1,
        )
        if (
            committed.case.status != CaseStatus.HUMAN_REVIEW
            or not committed.case.timeline
            or committed.case.timeline[-1].object_ref != receipt.receipt_id
        ):
            raise RepositoryIntegrityError(
                "persisted human-review roots lack their exact Case transition"
            )
        self._verify_transition_audit(
            connection,
            run_id=run_id,
            audit_sequence=expected_audit_head.sequence + 1,
            expected_head=expected_audit_head,
            object_id=receipt.case_id,
            object_kind=ArtifactKind.CASE,
        )
        return HearingHumanReviewResult(
            case=committed,
            receipt=receipt,
            checkpoint=checkpoint,
            created=False,
        )

    def claim_acquisition_execution(
        self,
        run_id: str,
        request: AcquisitionRequest,
        execution_mode: AcquisitionExecutionMode,
        owner_token: str,
    ) -> AcquisitionExecutionClaim:
        """Durably fence one acquisition before its tool boundary is crossed."""

        require_reference_token(run_id, "hearing repository run_id")
        validated = AcquisitionRequest.model_validate(request.model_dump(mode="json"))
        if validated.run_id != run_id:
            raise ContractViolation("acquisition request belongs to another run")
        if not isinstance(execution_mode, AcquisitionExecutionMode):
            raise TypeError("execution_mode must be an AcquisitionExecutionMode")
        owner_sha256 = self._acquisition_owner_sha256(owner_token)
        now, now_text, expiry, expiry_text = self._acquisition_claim_times()
        request_document = _contract_document(validated)
        request_document_sha256 = self._canonical_document_sha256(request_document)
        initial_claim_document, initial_claim_sha256 = self._acquisition_claim_document(
            request=validated,
            execution_mode=execution_mode,
            status=AcquisitionExecutionClaimState.ACTIVE,
            owner_token_sha256=owner_sha256,
            owner_fence=1,
            lease_expires_at=expiry_text,
            execution_publication_id=None,
            created_at=now_text,
            updated_at=now_text,
        )

        try:
            with self._host._immediate(require_m4=True) as connection:
                self._validate_pending_acquisition_request(connection, validated)
                row = connection.execute(
                    """
                    SELECT * FROM m4_acquisition_execution_claims
                    WHERE run_id = ? AND acquisition_request_id = ?
                    """,
                    (run_id, validated.request_id),
                ).fetchone()
                if row is None:
                    connection.execute(
                        """
                        INSERT INTO m4_acquisition_execution_claims(
                            run_id, acquisition_request_id,
                            request_document_sha256, request_json, case_id, hearing_id,
                            execution_mode, idempotency_key, status,
                            owner_token_sha256, owner_fence, lease_expires_at,
                            execution_publication_id, created_at, updated_at,
                            claim_json, document_sha256
                        ) VALUES (
                            ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?, 1, ?, NULL, ?, ?, ?, ?
                        )
                        """,
                        (
                            run_id,
                            validated.request_id,
                            request_document_sha256,
                            request_document,
                            validated.case_id,
                            validated.hearing_session_id,
                            execution_mode.value,
                            validated.request_id,
                            owner_sha256,
                            expiry_text,
                            now_text,
                            now_text,
                            initial_claim_document,
                            initial_claim_sha256,
                        ),
                    )
                    self._host._fault("hearing.acquisition.claim.before_commit")
                    return AcquisitionExecutionClaim(
                        status=AcquisitionExecutionClaimStatus.ACQUIRED,
                        request_id=validated.request_id,
                        execution_mode=execution_mode,
                        idempotency_key=validated.request_id,
                        owner_fence=1,
                        lease_expires_at=expiry,
                    )

                self._validate_acquisition_claim_row(
                    row,
                    request=validated,
                    execution_mode=execution_mode,
                    request_document_sha256=request_document_sha256,
                )
                stored_status = _row_str(row, "status")
                if stored_status == "COMPLETED":
                    return self._acquisition_claim_from_row(
                        row, status=AcquisitionExecutionClaimStatus.COMPLETED
                    )
                if stored_status == "ABANDONED":
                    return self._acquisition_claim_from_row(
                        row, status=AcquisitionExecutionClaimStatus.ABANDONED
                    )
                if stored_status != "ACTIVE":
                    raise RepositoryIntegrityError(
                        "acquisition execution claim has an invalid status"
                    )
                stored_expiry = _parse_utc_timestamp(
                    _row_str(row, "lease_expires_at"),
                    "acquisition execution claim expiry",
                )
                if stored_expiry > now:
                    return self._acquisition_claim_from_row(
                        row, status=AcquisitionExecutionClaimStatus.WAITING
                    )
                if execution_mode == AcquisitionExecutionMode.IDEMPOTENT_EXTERNAL:
                    return self._acquisition_claim_from_row(
                        row,
                        status=AcquisitionExecutionClaimStatus.EXPIRED_REQUIRES_RECOVERY,
                    )

                next_fence = _row_int(row, "owner_fence") + 1
                claim_document, claim_sha256 = self._acquisition_claim_document(
                    request=validated,
                    execution_mode=execution_mode,
                    status=AcquisitionExecutionClaimState.ACTIVE,
                    owner_token_sha256=owner_sha256,
                    owner_fence=next_fence,
                    lease_expires_at=expiry_text,
                    execution_publication_id=None,
                    created_at=_row_str(row, "created_at"),
                    updated_at=now_text,
                )
                updated = connection.execute(
                    """
                    UPDATE m4_acquisition_execution_claims
                    SET owner_token_sha256 = ?, owner_fence = ?,
                        lease_expires_at = ?, updated_at = ?,
                        claim_json = ?, document_sha256 = ?
                    WHERE run_id = ? AND acquisition_request_id = ?
                      AND status = 'ACTIVE' AND owner_fence = ?
                      AND lease_expires_at <= ?
                    """,
                    (
                        owner_sha256,
                        next_fence,
                        expiry_text,
                        now_text,
                        claim_document,
                        claim_sha256,
                        run_id,
                        validated.request_id,
                        _row_int(row, "owner_fence"),
                        now_text,
                    ),
                )
                if updated.rowcount != 1:
                    raise ConcurrentModification(
                        "acquisition execution claim takeover CAS was lost"
                    )
                self._host._fault("hearing.acquisition.claim.before_commit")
                return AcquisitionExecutionClaim(
                    status=AcquisitionExecutionClaimStatus.ACQUIRED,
                    request_id=validated.request_id,
                    execution_mode=execution_mode,
                    idempotency_key=validated.request_id,
                    owner_fence=next_fence,
                    lease_expires_at=expiry,
                )
        except sqlite3.IntegrityError as exc:
            raise ContractViolation("acquisition execution claim authority was rejected") from exc

    def claim_acquisition_recovery(
        self,
        run_id: str,
        request: AcquisitionRequest,
        observed_owner_fence: int,
        owner_token: str,
    ) -> AcquisitionExecutionClaim:
        """Grant a new fence only after the external executor resolved delivery."""

        require_reference_token(run_id, "hearing repository run_id")
        validated = AcquisitionRequest.model_validate(request.model_dump(mode="json"))
        self._require_acquisition_fence(observed_owner_fence)
        owner_sha256 = self._acquisition_owner_sha256(owner_token)
        now, now_text, expiry, expiry_text = self._acquisition_claim_times()
        request_document_sha256 = self._canonical_document_sha256(_contract_document(validated))
        try:
            with self._host._immediate(require_m4=True) as connection:
                self._validate_pending_acquisition_request(connection, validated)
                row = connection.execute(
                    """
                    SELECT * FROM m4_acquisition_execution_claims
                    WHERE run_id = ? AND acquisition_request_id = ?
                    """,
                    (run_id, validated.request_id),
                ).fetchone()
                if row is None:
                    raise ContractViolation(
                        "acquisition recovery requires a durable execution claim"
                    )
                self._validate_acquisition_claim_row(
                    row,
                    request=validated,
                    execution_mode=AcquisitionExecutionMode.IDEMPOTENT_EXTERNAL,
                    request_document_sha256=request_document_sha256,
                )
                stored_status = _row_str(row, "status")
                if stored_status == "COMPLETED":
                    return self._acquisition_claim_from_row(
                        row, status=AcquisitionExecutionClaimStatus.COMPLETED
                    )
                if stored_status == "ABANDONED":
                    return self._acquisition_claim_from_row(
                        row, status=AcquisitionExecutionClaimStatus.ABANDONED
                    )
                stored_expiry = _parse_utc_timestamp(
                    _row_str(row, "lease_expires_at"),
                    "acquisition execution claim expiry",
                )
                if _row_int(row, "owner_fence") != observed_owner_fence or stored_expiry > now:
                    return self._acquisition_claim_from_row(
                        row, status=AcquisitionExecutionClaimStatus.WAITING
                    )
                next_fence = observed_owner_fence + 1
                claim_document, claim_sha256 = self._acquisition_claim_document(
                    request=validated,
                    execution_mode=AcquisitionExecutionMode.IDEMPOTENT_EXTERNAL,
                    status=AcquisitionExecutionClaimState.ACTIVE,
                    owner_token_sha256=owner_sha256,
                    owner_fence=next_fence,
                    lease_expires_at=expiry_text,
                    execution_publication_id=None,
                    created_at=_row_str(row, "created_at"),
                    updated_at=now_text,
                )
                updated = connection.execute(
                    """
                    UPDATE m4_acquisition_execution_claims
                    SET owner_token_sha256 = ?, owner_fence = ?,
                        lease_expires_at = ?, updated_at = ?,
                        claim_json = ?, document_sha256 = ?
                    WHERE run_id = ? AND acquisition_request_id = ?
                      AND status = 'ACTIVE' AND owner_fence = ?
                      AND lease_expires_at <= ?
                    """,
                    (
                        owner_sha256,
                        next_fence,
                        expiry_text,
                        now_text,
                        claim_document,
                        claim_sha256,
                        run_id,
                        validated.request_id,
                        observed_owner_fence,
                        now_text,
                    ),
                )
                if updated.rowcount != 1:
                    raise ConcurrentModification("acquisition recovery fence CAS was lost")
                self._host._fault("hearing.acquisition.recovery_claim.before_commit")
                return AcquisitionExecutionClaim(
                    status=AcquisitionExecutionClaimStatus.ACQUIRED,
                    request_id=validated.request_id,
                    execution_mode=AcquisitionExecutionMode.IDEMPOTENT_EXTERNAL,
                    idempotency_key=validated.request_id,
                    owner_fence=next_fence,
                    lease_expires_at=expiry,
                )
        except sqlite3.IntegrityError as exc:
            raise ContractViolation("acquisition recovery fence was rejected") from exc

    def complete_acquisition_execution(
        self,
        run_id: str,
        publication: AcquisitionExecutionPublication,
        owner_token: str,
    ) -> AcquisitionExecutionCommit:
        """Atomically publish one exact tool result and close its current fence."""

        require_reference_token(run_id, "hearing repository run_id")
        validated = AcquisitionExecutionPublication.model_validate(
            publication.model_dump(mode="json")
        )
        if validated.request.run_id != run_id:
            raise ContractViolation("acquisition publication belongs to another run")
        owner_sha256 = self._acquisition_owner_sha256(owner_token)
        if validated.claim_owner_sha256 != owner_sha256:
            raise ConcurrentModification(
                "acquisition publication owner does not hold the claimed secret"
            )
        now_text = _utc_timestamp(self._host._clock)
        execution = self._execution_from_publication(validated)
        created = False
        try:
            with self._host._immediate(require_m4=True) as connection:
                row = connection.execute(
                    """
                    SELECT * FROM m4_acquisition_execution_claims
                    WHERE run_id = ? AND acquisition_request_id = ?
                    """,
                    (run_id, validated.request.request_id),
                ).fetchone()
                if row is None:
                    raise ContractViolation(
                        "acquisition completion requires a durable execution claim"
                    )
                self._validate_acquisition_claim_row(
                    row,
                    request=validated.request,
                    execution_mode=validated.execution_mode,
                    request_document_sha256=self._canonical_document_sha256(
                        _contract_document(validated.request)
                    ),
                )
                if _row_str(row, "status") == "COMPLETED":
                    stored = self._load_acquisition_execution_publication(
                        connection,
                        run_id,
                        _row_str(row, "execution_publication_id"),
                    )
                    if stored != validated:
                        raise HearingPersistenceConflict(
                            "completed acquisition execution conflicts with replay"
                        )
                    return AcquisitionExecutionCommit(publication=stored, created=False)
                if _row_str(row, "status") != "ACTIVE":
                    raise ConcurrentModification(
                        "acquisition execution claim is no longer completable"
                    )
                if (
                    _row_str(row, "owner_token_sha256") != owner_sha256
                    or _row_int(row, "owner_fence") != validated.claim_fence
                    or _row_str(row, "lease_expires_at") <= now_text
                ):
                    raise ConcurrentModification(
                        "acquisition execution completion lost its owner fence"
                    )

                loaded_case = self._host._load_case(
                    connection,
                    run_id,
                    validated.request.case_id,
                )
                source_pack = self._validate_acquisition_preconditions(
                    connection,
                    case=loaded_case.snapshot.case,
                    request=validated.request,
                    execution_manifest=validated.execution_manifest,
                )
                self._insert_tool_execution_manifest(connection, validated.execution_manifest)
                self._host._fault("hearing.acquisition.execution.after_manifest")
                self._insert_acquisition_outputs(
                    connection,
                    execution,
                    source_pack=source_pack,
                )
                self._host._fault("hearing.acquisition.execution.after_outputs")
                self._insert_acquisition_execution_publication(connection, validated)
                self._host._fault("hearing.acquisition.execution.before_claim_close")
                claim_document, claim_sha256 = self._acquisition_claim_document(
                    request=validated.request,
                    execution_mode=validated.execution_mode,
                    status=AcquisitionExecutionClaimState.COMPLETED,
                    owner_token_sha256=owner_sha256,
                    owner_fence=validated.claim_fence,
                    lease_expires_at=None,
                    execution_publication_id=validated.publication_id,
                    created_at=_row_str(row, "created_at"),
                    updated_at=now_text,
                )
                updated = connection.execute(
                    """
                    UPDATE m4_acquisition_execution_claims
                    SET status = 'COMPLETED', lease_expires_at = NULL,
                        execution_publication_id = ?, updated_at = ?,
                        claim_json = ?, document_sha256 = ?
                    WHERE run_id = ? AND acquisition_request_id = ?
                      AND status = 'ACTIVE' AND owner_token_sha256 = ?
                      AND owner_fence = ? AND lease_expires_at > ?
                    """,
                    (
                        validated.publication_id,
                        now_text,
                        claim_document,
                        claim_sha256,
                        run_id,
                        validated.request.request_id,
                        owner_sha256,
                        validated.claim_fence,
                        now_text,
                    ),
                )
                if updated.rowcount != 1:
                    raise ConcurrentModification("acquisition execution completion CAS was lost")
                self._host._fault("hearing.acquisition.execution.before_commit")
                created = True
        except sqlite3.IntegrityError as exc:
            raise ContractViolation(
                "acquisition execution publication authority was rejected"
            ) from exc
        commit = AcquisitionExecutionCommit(publication=validated, created=created)
        if created:
            # This fault is intentionally outside the transaction: tests and
            # operators can prove a crash after durable delivery publication.
            self._host._fault("hearing.acquisition.after_execution_publication")
        return commit

    def abandon_acquisition_execution(
        self,
        run_id: str,
        request: AcquisitionRequest,
        observed_owner_fence: int,
        owner_token: str,
    ) -> AcquisitionExecutionClaim:
        """Terminally fence unknown delivery so no worker can blindly retry it."""

        require_reference_token(run_id, "hearing repository run_id")
        validated = AcquisitionRequest.model_validate(request.model_dump(mode="json"))
        self._require_acquisition_fence(observed_owner_fence)
        owner_sha256 = self._acquisition_owner_sha256(owner_token)
        now_text = _utc_timestamp(self._host._clock)
        try:
            with self._host._immediate(require_m4=True) as connection:
                row = connection.execute(
                    """
                    SELECT * FROM m4_acquisition_execution_claims
                    WHERE run_id = ? AND acquisition_request_id = ?
                    """,
                    (run_id, validated.request_id),
                ).fetchone()
                if row is None:
                    raise ContractViolation(
                        "acquisition abandonment requires a durable execution claim"
                    )
                self._validate_acquisition_claim_row(
                    row,
                    request=validated,
                    execution_mode=AcquisitionExecutionMode(_row_str(row, "execution_mode")),
                    request_document_sha256=self._canonical_document_sha256(
                        _contract_document(validated)
                    ),
                )
                stored_status = _row_str(row, "status")
                if stored_status == "COMPLETED":
                    return self._acquisition_claim_from_row(
                        row, status=AcquisitionExecutionClaimStatus.COMPLETED
                    )
                if stored_status == "ABANDONED":
                    return self._acquisition_claim_from_row(
                        row, status=AcquisitionExecutionClaimStatus.ABANDONED
                    )
                if _row_int(row, "owner_fence") != observed_owner_fence:
                    raise ConcurrentModification(
                        "stale acquisition owner cannot abandon a newer fence"
                    )
                owned = _row_str(row, "owner_token_sha256") == owner_sha256
                expired_external_recovery = (
                    AcquisitionExecutionMode(_row_str(row, "execution_mode"))
                    == AcquisitionExecutionMode.IDEMPOTENT_EXTERNAL
                    and _row_str(row, "lease_expires_at") <= now_text
                )
                if not owned and not expired_external_recovery:
                    raise ConcurrentModification(
                        "acquisition abandonment lacks owner or recovery authority"
                    )
                next_fence = observed_owner_fence + 1
                stored_mode = AcquisitionExecutionMode(_row_str(row, "execution_mode"))
                claim_document, claim_sha256 = self._acquisition_claim_document(
                    request=validated,
                    execution_mode=stored_mode,
                    status=AcquisitionExecutionClaimState.ABANDONED,
                    owner_token_sha256=owner_sha256,
                    owner_fence=next_fence,
                    lease_expires_at=None,
                    execution_publication_id=None,
                    created_at=_row_str(row, "created_at"),
                    updated_at=now_text,
                )
                updated = connection.execute(
                    """
                    UPDATE m4_acquisition_execution_claims
                    SET status = 'ABANDONED', owner_token_sha256 = ?, owner_fence = ?,
                        lease_expires_at = NULL, updated_at = ?,
                        claim_json = ?, document_sha256 = ?
                    WHERE run_id = ? AND acquisition_request_id = ?
                      AND status = 'ACTIVE' AND owner_fence = ?
                    """,
                    (
                        owner_sha256,
                        next_fence,
                        now_text,
                        claim_document,
                        claim_sha256,
                        run_id,
                        validated.request_id,
                        observed_owner_fence,
                    ),
                )
                if updated.rowcount != 1:
                    raise ConcurrentModification("acquisition abandonment CAS was lost")
                self._host._fault("hearing.acquisition.abandon.before_commit")
                return AcquisitionExecutionClaim(
                    status=AcquisitionExecutionClaimStatus.ABANDONED,
                    request_id=validated.request_id,
                    execution_mode=stored_mode,
                    idempotency_key=validated.request_id,
                    owner_fence=next_fence,
                )
        except sqlite3.IntegrityError as exc:
            raise ContractViolation("acquisition abandonment was rejected") from exc

    def load_acquisition_execution(
        self,
        run_id: str,
        request_id: str,
    ) -> AcquisitionExecutionPublication | None:
        require_reference_token(run_id, "hearing repository run_id")
        require_reference_token(request_id, "acquisition request ID")
        connection = self._host._connection(require_hardening=True, require_m4=True)
        try:
            row = connection.execute(
                """
                SELECT execution_publication_id
                FROM m4_acquisition_execution_publications
                WHERE run_id = ? AND acquisition_request_id = ?
                """,
                (run_id, request_id),
            ).fetchone()
            if row is None:
                return None
            return self._load_acquisition_execution_publication(
                connection,
                run_id,
                _row_str(row, "execution_publication_id"),
            )
        finally:
            connection.close()

    def persist_acquisition_successor(
        self,
        run_id: str,
        expected_case_revision: int,
        expected_audit_head: AuditHead,
        request: AcquisitionRequest,
        publication: AcquisitionExecutionPublication,
    ) -> AcquisitionPublishResult:
        """Publish one independently reclosed M4 pack successor under dual CAS."""

        require_reference_token(run_id, "hearing repository run_id")
        self._require_expected_case_revision(expected_case_revision)
        validated_request = AcquisitionRequest.model_validate(request.model_dump(mode="json"))
        validated_publication = AcquisitionExecutionPublication.model_validate(
            publication.model_dump(mode="json")
        )
        if validated_request.run_id != run_id or validated_publication.request != validated_request:
            raise ContractViolation("acquisition request belongs to another run")
        execution = self._execution_from_publication(validated_publication)
        validated_manifest = validated_publication.execution_manifest
        validated_result = validated_publication.tool_result
        loaded_outputs = execution.output_objects

        try:
            with self._host._immediate(require_m4=True) as connection:
                claim_row = connection.execute(
                    """
                    SELECT execution_publication_id
                    FROM m4_acquisition_execution_claims
                    WHERE run_id = ? AND acquisition_request_id = ?
                      AND status = 'COMPLETED'
                    """,
                    (run_id, validated_request.request_id),
                ).fetchone()
                if claim_row is None:
                    raise ContractViolation(
                        "acquisition pack publication requires a completed execution"
                    )
                stored_publication = self._load_acquisition_execution_publication(
                    connection,
                    run_id,
                    _row_str(claim_row, "execution_publication_id"),
                )
                if stored_publication != validated_publication:
                    raise HearingPersistenceConflict(
                        "acquisition pack publication conflicts with durable execution"
                    )
                existing_receipt = connection.execute(
                    """
                    SELECT receipt_id FROM m4_tool_execution_receipts
                    WHERE run_id = ? AND acquisition_request_id = ?
                    """,
                    (run_id, validated_request.request_id),
                ).fetchone()
                if existing_receipt is not None:
                    return self._replay_acquisition_successor(
                        connection,
                        run_id=run_id,
                        expected_case_revision=expected_case_revision,
                        expected_audit_head=expected_audit_head,
                        execution=execution,
                        receipt_id=_row_str(existing_receipt, "receipt_id"),
                    )

                loaded_case = self._host._load_case(
                    connection,
                    run_id,
                    validated_request.case_id,
                )
                if loaded_case.snapshot.revision != expected_case_revision:
                    raise ConcurrentModification(
                        "case revision changed before acquisition publication"
                    )
                head = self._host._validated_head(connection, run_id)
                self._require_expected_head(head, expected_audit_head)
                case = loaded_case.snapshot.case
                current = self._validate_acquisition_preconditions(
                    connection,
                    case=case,
                    request=validated_request,
                    execution_manifest=validated_manifest,
                )
                current_authority = self._load_hearing_evidence_authority(
                    connection,
                    run_id=run_id,
                    hearing_id=validated_request.hearing_session_id,
                    current_pack_id=current.pack_id,
                )
                try:
                    draft = derive_evidence_pack_successor(
                        current,
                        execution,
                        current_receipts=current_authority.receipts,
                        current_loaded_objects=current_authority.loaded_objects,
                    )
                except (AcquisitionAuthorityError, EvidenceAuthorityError) as exc:
                    raise ContractViolation(
                        "acquisition cannot derive a legal evidence successor"
                    ) from exc

                successor = self._close_acquisition_draft(
                    draft,
                    physical_crops=tuple(
                        sorted(
                            (*draft.crops, *loaded_outputs.crops),
                            key=lambda crop: crop.crop_id,
                        )
                    ),
                )
                receipt = ToolExecutionReceipt(
                    request=validated_request,
                    execution_manifest=validated_manifest,
                    tool_result=validated_result,
                    resulting_evidence_pack_id=successor.pack_id,
                    resulting_evidence_pack_version=successor.version,
                )
                try:
                    validate_evidence_pack_successor(
                        current,
                        successor,
                        receipt,
                        current_receipts=current_authority.receipts,
                        loaded_objects=merge_loaded_evidence_objects(
                            current_authority.loaded_objects,
                            loaded_outputs,
                        ),
                    )
                except (EvidenceAuthorityError, EvidencePackSuccessorError) as exc:
                    raise ContractViolation(
                        "reclosed acquisition successor failed lineage validation"
                    ) from exc
                cycle_scope_id, cycle_scope_sha256 = self._acquisition_cycle_scope_id(
                    connection,
                    validated_request,
                )
                derivation = EvidencePackDerivation(
                    run_id=run_id,
                    case_id=validated_request.case_id,
                    hearing_session_id=validated_request.hearing_session_id,
                    source_cycle_scope_id=cycle_scope_id,
                    source_cycle_scope_sha256=cycle_scope_sha256,
                    previous_evidence_pack_id=current.pack_id,
                    previous_evidence_pack_version=current.version,
                    new_evidence_pack_id=successor.pack_id,
                    new_evidence_pack_version=successor.version,
                    tool_execution_receipt_id=receipt.receipt_id,
                    manifest_id=validated_request.manifest_id,
                )
                audit_sequence = head.sequence + 1
                self._insert_acquisition_pack(
                    connection,
                    successor,
                    created_audit_sequence=audit_sequence,
                )
                self._host._fault("hearing.acquisition.after_pack")
                self._insert_tool_execution_receipt(
                    connection,
                    receipt,
                    cycle_scope_id=derivation.source_cycle_scope_id,
                    cycle_scope_sha256=derivation.source_cycle_scope_sha256,
                )
                self._insert_evidence_pack_derivation(connection, derivation)
                self._host._fault("hearing.acquisition.after_receipt")
                new_case = self._case_with_updates(
                    case,
                    status=CaseStatus.DELIBERATING,
                    timeline_entry=TimelineEntry(
                        sequence=len(case.timeline),
                        action=AuditAction.CASE_STATE_CHANGED.value,
                        stage="HEARING",
                        object_ref=receipt.receipt_id,
                        details={
                            "action": validated_request.action.value,
                            "evidence_pack_id": successor.pack_id,
                            "evidence_pack_version": successor.version,
                            "tool_receipt_id": receipt.receipt_id,
                        },
                    ),
                    evidence_packs=(*case.evidence_packs, successor),
                )
                committed = self._commit_case_version(
                    connection,
                    previous=loaded_case.snapshot,
                    previous_document_sha256=loaded_case.document_sha256,
                    new_case=new_case,
                    expected_head=head,
                    object_ref=ArtifactRef(
                        kind=ArtifactKind.CASE,
                        artifact_id=validated_request.case_id,
                    ),
                    fault_prefix="hearing.acquisition",
                    audit_action=AuditAction.EVIDENCE_PACK_PUBLISHED,
                    latest_pack_id=successor.pack_id,
                    latest_pack_version=successor.version,
                )
                self._host._fault("hearing.acquisition.before_commit")
                return AcquisitionPublishResult(
                    case=committed,
                    pack=successor,
                    receipt=receipt,
                    created=True,
                )
        except sqlite3.IntegrityError as exc:
            raise ContractViolation("acquisition publication transaction was rejected") from exc

    @staticmethod
    def _acquisition_owner_sha256(owner_token: str) -> str:
        if not isinstance(owner_token, str) or not 32 <= len(owner_token) <= 512:
            raise ValueError("acquisition claim owner token has an invalid length")
        return hashlib.sha256(owner_token.encode("utf-8")).hexdigest()

    @staticmethod
    def _require_acquisition_fence(owner_fence: int) -> None:
        if not isinstance(owner_fence, int) or isinstance(owner_fence, bool) or owner_fence <= 0:
            raise ValueError("acquisition owner fence must be positive")

    @classmethod
    def _acquisition_claim_document(
        cls,
        *,
        request: AcquisitionRequest,
        execution_mode: AcquisitionExecutionMode,
        status: AcquisitionExecutionClaimState,
        owner_token_sha256: str,
        owner_fence: int,
        lease_expires_at: str | None,
        execution_publication_id: str | None,
        created_at: str,
        updated_at: str,
    ) -> tuple[str, str]:
        authority = AcquisitionExecutionClaimAuthority(
            request=request,
            execution_mode=execution_mode,
            idempotency_key=request.request_id,
            status=status,
            owner_token_sha256=owner_token_sha256,
            owner_fence=owner_fence,
            lease_expires_at=lease_expires_at,
            execution_publication_id=execution_publication_id,
            created_at=created_at,
            updated_at=updated_at,
        )
        document = _contract_document(authority)
        return document, cls._canonical_document_sha256(document)

    def _acquisition_claim_times(self) -> tuple[datetime, str, datetime, str]:
        try:
            observed = self._host._clock()
            now_text = _canonical_utc_timestamp(observed, "repository clock")
            now = observed.astimezone(UTC)
            expiry = now + timedelta(seconds=_ACQUISITION_EXECUTION_LEASE_SECONDS)
            expiry_text = _canonical_utc_timestamp(expiry, "acquisition execution claim expiry")
        except (AttributeError, TypeError, ValueError) as exc:
            raise ContractViolation(
                "repository clock must return a timezone-aware datetime"
            ) from exc
        return now, now_text, expiry, expiry_text

    def _validate_pending_acquisition_request(
        self,
        connection: sqlite3.Connection,
        request: AcquisitionRequest,
    ) -> None:
        durable = self._load_acquisition_request(connection, request.run_id, request.request_id)
        if durable != request:
            raise HearingPersistenceConflict("acquisition claim differs from its durable request")
        loaded_case = self._host._load_case(connection, request.run_id, request.case_id)
        case = loaded_case.snapshot.case
        if (
            case.status != CaseStatus.DELIBERATING
            or case.manifest_id != request.manifest_id
            or not case.evidence_packs
            or case.evidence_packs[-1].pack_id != request.current_evidence_pack_id
            or case.evidence_packs[-1].version != request.current_evidence_pack_version
            or not case.evidence_packs[-1].complete
        ):
            raise ConcurrentModification("Case is no longer the pending acquisition authority")
        latest = self._load_latest_hearing_checkpoint(
            connection, request.run_id, request.hearing_session_id
        )
        if (
            latest.phase != HearingCheckpointPhase.ACQUISITION_PENDING
            or latest.acquisition_request != request
            or latest.tool_execution_receipt is not None
            or latest.current_evidence_pack_id != request.current_evidence_pack_id
            or latest.current_evidence_pack_version != request.current_evidence_pack_version
        ):
            raise ConcurrentModification(
                "latest hearing checkpoint is not this pending acquisition"
            )
        session = self._load_hearing_session(connection, request.run_id, request.hearing_session_id)
        if (
            session.case_id != request.case_id
            or session.manifest_id != request.manifest_id
            or request.prior_acquisition_rounds >= session.acquisition_round_limit
        ):
            raise ContractViolation("hearing acquisition limit or scope is invalid")
        completed_count = _row_int(
            connection.execute(
                """
                SELECT COUNT(*) AS completed_count
                FROM m4_tool_execution_receipts
                WHERE run_id = ? AND hearing_id = ?
                """,
                (request.run_id, request.hearing_session_id),
            ).fetchone(),
            "completed_count",
        )
        if completed_count != request.prior_acquisition_rounds:
            raise ConcurrentModification(
                "hearing acquisition history changed before execution claim"
            )

    @staticmethod
    def _validate_acquisition_claim_row(
        row: sqlite3.Row,
        *,
        request: AcquisitionRequest,
        execution_mode: AcquisitionExecutionMode,
        request_document_sha256: str,
    ) -> None:
        raw = _row_str(row, "claim_json")
        try:
            authority = AcquisitionExecutionClaimAuthority.model_validate_json(raw)
            expected_authority = AcquisitionExecutionClaimAuthority(
                request=request,
                execution_mode=execution_mode,
                idempotency_key=request.request_id,
                status=AcquisitionExecutionClaimState(_row_str(row, "status")),
                owner_token_sha256=_row_str(row, "owner_token_sha256"),
                owner_fence=_row_int(row, "owner_fence"),
                lease_expires_at=_row_optional_str(row, "lease_expires_at"),
                execution_publication_id=_row_optional_str(row, "execution_publication_id"),
                created_at=_row_str(row, "created_at"),
                updated_at=_row_str(row, "updated_at"),
            )
        except (ValidationError, TypeError, ValueError) as exc:
            raise RepositoryIntegrityError("stored acquisition execution claim is invalid") from exc
        _verify_document(raw, _row_str(row, "document_sha256"), authority)
        if authority != expected_authority:
            raise RepositoryIntegrityError(
                "acquisition execution claim document conflicts with its state"
            )
        indexed = (
            _row_str(row, "run_id"),
            _row_str(row, "acquisition_request_id"),
            _row_str(row, "request_document_sha256"),
            _row_str(row, "request_json"),
            _row_str(row, "case_id"),
            _row_str(row, "hearing_id"),
            _row_str(row, "execution_mode"),
            _row_str(row, "idempotency_key"),
        )
        expected = (
            request.run_id,
            request.request_id,
            request_document_sha256,
            _contract_document(request),
            request.case_id,
            request.hearing_session_id,
            execution_mode.value,
            request.request_id,
        )
        if indexed != expected:
            raise HearingPersistenceConflict(
                "acquisition execution claim conflicts with its request or mode"
            )

    @staticmethod
    def _acquisition_claim_from_row(
        row: sqlite3.Row,
        *,
        status: AcquisitionExecutionClaimStatus,
    ) -> AcquisitionExecutionClaim:
        lease_expires_at = None
        publication_id = None
        if status in {
            AcquisitionExecutionClaimStatus.ACQUIRED,
            AcquisitionExecutionClaimStatus.WAITING,
            AcquisitionExecutionClaimStatus.EXPIRED_REQUIRES_RECOVERY,
        }:
            lease_expires_at = _parse_utc_timestamp(
                _row_str(row, "lease_expires_at"),
                "acquisition execution claim expiry",
            )
        elif status == AcquisitionExecutionClaimStatus.COMPLETED:
            publication_id = _row_str(row, "execution_publication_id")
        return AcquisitionExecutionClaim(
            status=status,
            request_id=_row_str(row, "acquisition_request_id"),
            execution_mode=AcquisitionExecutionMode(_row_str(row, "execution_mode")),
            idempotency_key=_row_str(row, "idempotency_key"),
            owner_fence=_row_int(row, "owner_fence"),
            lease_expires_at=lease_expires_at,
            publication_id=publication_id,
        )

    @staticmethod
    def _execution_from_publication(
        publication: AcquisitionExecutionPublication,
    ) -> AcquisitionExecution:
        try:
            return AcquisitionExecution(
                request=publication.request,
                execution_manifest=publication.execution_manifest,
                tool_result=publication.tool_result,
                output_objects=LoadedEvidenceObjects(
                    frames=publication.frames,
                    crops=publication.crops,
                    objective_facts=publication.objective_facts,
                    detections=publication.detections,
                ),
                crop_request=publication.crop_request,
            )
        except (AcquisitionAuthorityError, EvidenceAuthorityError, ValueError) as exc:
            raise ContractViolation(
                "acquisition execution publication is not authoritative"
            ) from exc

    def _insert_acquisition_execution_publication(
        self,
        connection: sqlite3.Connection,
        publication: AcquisitionExecutionPublication,
    ) -> None:
        document = _contract_document(publication)
        request_document = _contract_document(publication.request)
        connection.execute(
            """
            INSERT INTO m4_acquisition_execution_publications(
                run_id, execution_publication_id, acquisition_request_id,
                request_document_sha256, case_id, hearing_id,
                execution_manifest_id, tool_result_id, execution_mode,
                idempotency_key, claim_owner_sha256, claim_fence,
                publication_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                publication.request.run_id,
                publication.publication_id,
                publication.request.request_id,
                self._canonical_document_sha256(request_document),
                publication.request.case_id,
                publication.request.hearing_session_id,
                publication.execution_manifest.execution_manifest_id,
                publication.tool_result.tool_result_id,
                publication.execution_mode.value,
                publication.idempotency_key,
                publication.claim_owner_sha256,
                publication.claim_fence,
                document,
                self._canonical_document_sha256(document),
            ),
        )

    def _load_acquisition_execution_publication(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        publication_id: str,
    ) -> AcquisitionExecutionPublication:
        row = connection.execute(
            """
            SELECT * FROM m4_acquisition_execution_publications
            WHERE run_id = ? AND execution_publication_id = ?
            """,
            (run_id, publication_id),
        ).fetchone()
        if row is None:
            raise EvidenceMissing(
                f"unknown acquisition execution publication in run {run_id}: {publication_id}"
            )
        raw = _row_str(row, "publication_json")
        try:
            publication = AcquisitionExecutionPublication.model_validate_json(raw)
        except ValidationError as exc:
            raise RepositoryIntegrityError(
                "stored acquisition execution publication is invalid"
            ) from exc
        _verify_document(raw, _row_str(row, "document_sha256"), publication)
        request_document_sha256 = self._canonical_document_sha256(
            _contract_document(publication.request)
        )
        indexed = (
            _row_str(row, "run_id"),
            _row_str(row, "execution_publication_id"),
            _row_str(row, "acquisition_request_id"),
            _row_str(row, "request_document_sha256"),
            _row_str(row, "case_id"),
            _row_str(row, "hearing_id"),
            _row_str(row, "execution_manifest_id"),
            _row_str(row, "tool_result_id"),
            _row_str(row, "execution_mode"),
            _row_str(row, "idempotency_key"),
            _row_str(row, "claim_owner_sha256"),
            _row_int(row, "claim_fence"),
        )
        expected = (
            publication.request.run_id,
            publication.publication_id,
            publication.request.request_id,
            request_document_sha256,
            publication.request.case_id,
            publication.request.hearing_session_id,
            publication.execution_manifest.execution_manifest_id,
            publication.tool_result.tool_result_id,
            publication.execution_mode.value,
            publication.idempotency_key,
            publication.claim_owner_sha256,
            publication.claim_fence,
        )
        if indexed != expected or run_id != publication.request.run_id:
            raise RepositoryIntegrityError(
                "acquisition execution publication indexes conflict with content"
            )
        request = self._load_acquisition_request(connection, run_id, publication.request.request_id)
        manifest = self._load_tool_execution_manifest(
            connection, run_id, publication.execution_manifest.execution_manifest_id
        )
        if request != publication.request or manifest != publication.execution_manifest:
            raise RepositoryIntegrityError(
                "acquisition execution publication roots conflict with content"
            )
        claim = connection.execute(
            """
            SELECT * FROM m4_acquisition_execution_claims
            WHERE run_id = ? AND acquisition_request_id = ?
            """,
            (run_id, publication.request.request_id),
        ).fetchone()
        if claim is None or (
            _row_str(claim, "status") != "COMPLETED"
            or _row_str(claim, "execution_publication_id") != publication.publication_id
            or _row_str(claim, "owner_token_sha256") != publication.claim_owner_sha256
            or _row_int(claim, "owner_fence") != publication.claim_fence
        ):
            raise RepositoryIntegrityError(
                "acquisition publication lacks its completed execution claim"
            )
        self._execution_from_publication(publication)
        return publication

    @staticmethod
    def _canonical_document_sha256(document: str) -> str:
        return hashlib.sha256(document.encode("utf-8")).hexdigest()

    def _insert_or_validate_acquisition_request(
        self,
        connection: sqlite3.Connection,
        request: AcquisitionRequest,
        *,
        cycle_scope_id: str,
        cycle_scope_sha256: str,
    ) -> None:
        """Persist the Judge-derived request before crossing the tool boundary."""

        rows = connection.execute(
            """
            SELECT acquisition_request_id
            FROM m4_acquisition_requests
            WHERE run_id = ?
              AND (
                  acquisition_request_id = ?
                  OR cycle_scope_id = ?
                  OR judge_output_id = ?
              )
            ORDER BY acquisition_request_id
            """,
            (
                request.run_id,
                request.request_id,
                cycle_scope_id,
                request.source_judge_output_id,
            ),
        ).fetchall()
        if rows:
            if len(rows) != 1:
                raise RepositoryIntegrityError(
                    "acquisition request indexes select multiple immutable roots"
                )
            stored = self._load_acquisition_request(
                connection,
                request.run_id,
                _row_str(rows[0], "acquisition_request_id"),
            )
            if stored != request:
                raise HearingPersistenceConflict(
                    "acquisition request identity conflicts with persisted content"
                )
            stored_scope = self._acquisition_cycle_scope_id(connection, stored)
            if stored_scope != (cycle_scope_id, cycle_scope_sha256):
                raise HearingPersistenceConflict(
                    "acquisition request conflicts with its checkpoint cycle"
                )
            return

        cycle = self._load_hearing_cycle(connection, request.run_id, cycle_scope_id)
        expected_cycle = (
            cycle.cycle_sha256,
            cycle.hearing_session_id,
            cycle.case_id,
            cycle.cycle_index,
            cycle.prior_acquisition_rounds,
            cycle.prior_rework_rounds,
            cycle.cycle_evidence_pack_id,
            cycle.cycle_evidence_pack_version,
            cycle.manifest_id,
        )
        requested_cycle = (
            cycle_scope_sha256,
            request.hearing_session_id,
            request.case_id,
            request.round_index,
            request.prior_acquisition_rounds,
            request.prior_rework_rounds,
            request.current_evidence_pack_id,
            request.current_evidence_pack_version,
            request.manifest_id,
        )
        if expected_cycle != requested_cycle:
            raise ContractViolation("acquisition request conflicts with its hearing cycle")
        document = _contract_document(request)
        parameters_document = canonical_json(request.validated_parameters.model_dump(mode="json"))
        connection.execute(
            """
            INSERT INTO m4_acquisition_requests(
                run_id, acquisition_request_id, hearing_id,
                cycle_scope_id, cycle_scope_sha256, case_id,
                round_index, prior_acquisition_rounds, prior_rework_rounds,
                evidence_pack_id, evidence_pack_version, judge_output_id,
                source_model_request_id, source_model_response_id, action,
                validated_parameters_sha256, manifest_id,
                request_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request.run_id,
                request.request_id,
                request.hearing_session_id,
                cycle_scope_id,
                cycle_scope_sha256,
                request.case_id,
                request.round_index,
                request.prior_acquisition_rounds,
                request.prior_rework_rounds,
                request.current_evidence_pack_id,
                request.current_evidence_pack_version,
                request.source_judge_output_id,
                request.source_model_request_ref.artifact_id,
                request.source_model_response_ref.artifact_id,
                request.action.value,
                self._canonical_document_sha256(parameters_document),
                request.manifest_id,
                document,
                self._canonical_document_sha256(document),
            ),
        )

    def _load_acquisition_request(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        request_id: str,
    ) -> AcquisitionRequest:
        row = connection.execute(
            """
            SELECT * FROM m4_acquisition_requests
            WHERE run_id = ? AND acquisition_request_id = ?
            """,
            (run_id, request_id),
        ).fetchone()
        if row is None:
            raise EvidenceMissing(f"unknown acquisition request in run {run_id}: {request_id}")
        raw = _row_str(row, "request_json")
        try:
            request = AcquisitionRequest.model_validate_json(raw)
        except ValidationError as exc:
            raise RepositoryIntegrityError(
                "stored acquisition request is not a valid contract"
            ) from exc
        _verify_document(raw, _row_str(row, "document_sha256"), request)
        parameters_document = canonical_json(request.validated_parameters.model_dump(mode="json"))
        indexed = (
            _row_str(row, "run_id"),
            _row_str(row, "acquisition_request_id"),
            _row_str(row, "hearing_id"),
            _row_str(row, "case_id"),
            _row_int(row, "round_index"),
            _row_int(row, "prior_acquisition_rounds"),
            _row_int(row, "prior_rework_rounds"),
            _row_str(row, "evidence_pack_id"),
            _row_int(row, "evidence_pack_version"),
            _row_str(row, "judge_output_id"),
            _row_str(row, "source_model_request_id"),
            _row_str(row, "source_model_response_id"),
            _row_str(row, "action"),
            _row_str(row, "validated_parameters_sha256"),
            _row_str(row, "manifest_id"),
        )
        expected = (
            request.run_id,
            request.request_id,
            request.hearing_session_id,
            request.case_id,
            request.round_index,
            request.prior_acquisition_rounds,
            request.prior_rework_rounds,
            request.current_evidence_pack_id,
            request.current_evidence_pack_version,
            request.source_judge_output_id,
            request.source_model_request_ref.artifact_id,
            request.source_model_response_ref.artifact_id,
            request.action.value,
            self._canonical_document_sha256(parameters_document),
            request.manifest_id,
        )
        if indexed != expected or request.run_id != run_id or request.request_id != request_id:
            raise RepositoryIntegrityError(
                "acquisition request indexes conflict with canonical content"
            )
        cycle = self._load_hearing_cycle(
            connection,
            run_id,
            _row_str(row, "cycle_scope_id"),
        )
        if (
            cycle.cycle_sha256 != _row_str(row, "cycle_scope_sha256")
            or cycle.hearing_session_id != request.hearing_session_id
            or cycle.case_id != request.case_id
            or cycle.cycle_index != request.round_index
            or cycle.prior_acquisition_rounds != request.prior_acquisition_rounds
            or cycle.prior_rework_rounds != request.prior_rework_rounds
            or cycle.cycle_evidence_pack_id != request.current_evidence_pack_id
            or cycle.cycle_evidence_pack_version != request.current_evidence_pack_version
            or cycle.manifest_id != request.manifest_id
        ):
            raise RepositoryIntegrityError(
                "acquisition request cycle indexes conflict with canonical content"
            )
        judge = self._load_hearing_role_output(
            connection,
            run_id,
            request.source_judge_output_id,
        )
        if not isinstance(judge.payload, JudgeModelPayload) or not isinstance(
            judge.payload.outcome,
            JudgeAcquisitionDecisionPayload,
        ):
            raise RepositoryIntegrityError(
                "acquisition request source is not a Judge acquisition output"
            )
        if (
            judge.role != VlmRole.JUDGE
            or judge.request_ref != request.source_model_request_ref
            or judge.response_ref != request.source_model_response_ref
            or judge.payload.outcome.request != request.request_payload
        ):
            raise RepositoryIntegrityError("acquisition request conflicts with its Judge output")
        return request

    def _acquisition_cycle_scope_id(
        self,
        connection: sqlite3.Connection,
        request: AcquisitionRequest,
    ) -> tuple[str, str]:
        row = connection.execute(
            """
            SELECT cycle_scope_id, cycle_scope_sha256
            FROM m4_acquisition_requests
            WHERE run_id = ? AND acquisition_request_id = ?
            """,
            (request.run_id, request.request_id),
        ).fetchone()
        if row is None:
            raise EvidenceMissing("acquisition request has not crossed its durable boundary")
        stored = self._load_acquisition_request(connection, request.run_id, request.request_id)
        if stored != request:
            raise HearingPersistenceConflict(
                "acquisition request differs from its durable checkpoint authority"
            )
        return _row_str(row, "cycle_scope_id"), _row_str(row, "cycle_scope_sha256")

    def _validate_acquisition_preconditions(
        self,
        connection: sqlite3.Connection,
        *,
        case: Case,
        request: AcquisitionRequest,
        execution_manifest: ToolExecutionManifest,
    ) -> EvidencePack:
        if (
            case.run_id != request.run_id
            or case.case_id != request.case_id
            or case.status != CaseStatus.DELIBERATING
            or case.manifest_id != request.manifest_id
            or not case.evidence_packs
        ):
            raise ConcurrentModification("Case is no longer the deliberating acquisition authority")
        current = case.evidence_packs[-1]
        if (
            current.pack_id != request.current_evidence_pack_id
            or current.version != request.current_evidence_pack_version
            or not current.complete
        ):
            raise ConcurrentModification("latest Case pack changed before acquisition publication")
        materialized = self._host._load_pack(connection, request.run_id, current.pack_id)
        if not isinstance(materialized, EvidencePack) or materialized != current:
            raise RepositoryIntegrityError(
                "Case acquisition pack differs from immutable pack authority"
            )
        durable_request = self._load_acquisition_request(
            connection,
            request.run_id,
            request.request_id,
        )
        if durable_request != request:
            raise HearingPersistenceConflict(
                "tool execution does not bind the durable acquisition request"
            )
        session = self._load_hearing_session(
            connection,
            request.run_id,
            request.hearing_session_id,
        )
        if (
            session.case_id != request.case_id
            or session.manifest_id != request.manifest_id
            or request.prior_acquisition_rounds >= session.acquisition_round_limit
        ):
            raise ContractViolation("hearing acquisition limit or scope is invalid")
        completed_count = _row_int(
            connection.execute(
                """
                SELECT COUNT(*) AS completed_count
                FROM m4_tool_execution_receipts
                WHERE run_id = ? AND hearing_id = ?
                """,
                (request.run_id, request.hearing_session_id),
            ).fetchone(),
            "completed_count",
        )
        if completed_count != request.prior_acquisition_rounds:
            raise ConcurrentModification(
                "hearing acquisition history changed before tool publication"
            )
        latest = self._load_latest_hearing_checkpoint(
            connection,
            request.run_id,
            request.hearing_session_id,
        )
        if (
            latest.phase != HearingCheckpointPhase.ACQUISITION_PENDING
            or latest.acquisition_request != request
            or latest.tool_execution_receipt is not None
            or latest.current_evidence_pack_id != current.pack_id
            or latest.current_evidence_pack_version != current.version
            or latest.cycle_evidence_pack_id != current.pack_id
            or latest.cycle_evidence_pack_version != current.version
        ):
            raise ConcurrentModification(
                "latest hearing checkpoint is not this pending acquisition"
            )
        cycle_scope_id, cycle_scope_sha256 = self._acquisition_cycle_scope_id(
            connection,
            request,
        )
        if (
            latest.cycle_scope_id != cycle_scope_id
            or latest.cycle_scope_sha256 != cycle_scope_sha256
        ):
            raise RepositoryIntegrityError(
                "pending acquisition request is attached to another cycle"
            )
        self._validate_execution_manifest_pin(
            connection,
            request=request,
            execution_manifest=execution_manifest,
        )
        return materialized

    def _validate_execution_manifest_pin(
        self,
        connection: sqlite3.Connection,
        *,
        request: AcquisitionRequest,
        execution_manifest: ToolExecutionManifest,
    ) -> None:
        if (
            execution_manifest.run_id != request.run_id
            or execution_manifest.case_id != request.case_id
            or execution_manifest.hearing_session_id != request.hearing_session_id
            or execution_manifest.acquisition_request_id != request.request_id
            or execution_manifest.action != request.action
            or execution_manifest.manifest_id != request.manifest_id
        ):
            raise ManifestMismatch("tool execution manifest conflicts with its request")
        expected_schema_id = sha256_hex(
            [
                "m4-acquisition-parameters-schema",
                1,
                request.action.value,
                type(request.validated_parameters).model_json_schema(mode="validation"),
            ]
        )
        if execution_manifest.parameters_schema_sha256 != expected_schema_id:
            raise ManifestMismatch("tool parameter schema is not the frozen action schema")
        run_manifest = self._host._load_run_manifest(connection, request.run_id)
        if run_manifest.manifest_id != request.manifest_id:
            raise ManifestMismatch("acquisition request does not use the run manifest")
        component_ids = {
            self._canonical_document_sha256(canonical_json(component.model_dump(mode="json")))
            for component in run_manifest.software_components.values()
        }
        if execution_manifest.component_manifest_id not in component_ids:
            raise ManifestMismatch(
                "tool implementation is absent from run software-component authority"
            )
        model_ids = {model.model_manifest_id for model in run_manifest.models.values()}
        if execution_manifest.model_manifest_id is not None and (
            execution_manifest.model_manifest_id not in model_ids
        ):
            raise ManifestMismatch("acquisition model is absent from the run manifest")

    def _insert_tool_execution_manifest(
        self,
        connection: sqlite3.Connection,
        manifest: ToolExecutionManifest,
    ) -> None:
        row = connection.execute(
            """
            SELECT execution_manifest_id
            FROM m4_tool_execution_manifests
            WHERE run_id = ? AND acquisition_request_id = ?
            """,
            (manifest.run_id, manifest.acquisition_request_id),
        ).fetchone()
        if row is not None:
            stored = self._load_tool_execution_manifest(
                connection,
                manifest.run_id,
                _row_str(row, "execution_manifest_id"),
            )
            if stored != manifest:
                raise HearingPersistenceConflict(
                    "tool execution manifest identity conflicts with persisted content"
                )
            return
        document = _contract_document(manifest)
        connection.execute(
            """
            INSERT INTO m4_tool_execution_manifests(
                run_id, execution_manifest_id, case_id, hearing_id,
                acquisition_request_id, action, tool_id, tool_revision,
                parameters_schema_sha256, component_manifest_id,
                model_manifest_id, manifest_id, manifest_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                manifest.run_id,
                manifest.execution_manifest_id,
                manifest.case_id,
                manifest.hearing_session_id,
                manifest.acquisition_request_id,
                manifest.action.value,
                manifest.tool_id,
                manifest.tool_revision,
                manifest.parameters_schema_sha256,
                manifest.component_manifest_id,
                manifest.model_manifest_id,
                manifest.manifest_id,
                document,
                self._canonical_document_sha256(document),
            ),
        )

    def _load_tool_execution_manifest(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        execution_manifest_id: str,
    ) -> ToolExecutionManifest:
        row = connection.execute(
            """
            SELECT * FROM m4_tool_execution_manifests
            WHERE run_id = ? AND execution_manifest_id = ?
            """,
            (run_id, execution_manifest_id),
        ).fetchone()
        if row is None:
            raise EvidenceMissing(
                f"unknown tool execution manifest in run {run_id}: {execution_manifest_id}"
            )
        raw = _row_str(row, "manifest_json")
        try:
            manifest = ToolExecutionManifest.model_validate_json(raw)
        except ValidationError as exc:
            raise RepositoryIntegrityError("stored tool execution manifest is invalid") from exc
        _verify_document(raw, _row_str(row, "document_sha256"), manifest)
        indexed = (
            _row_str(row, "run_id"),
            _row_str(row, "execution_manifest_id"),
            _row_str(row, "case_id"),
            _row_str(row, "hearing_id"),
            _row_str(row, "acquisition_request_id"),
            _row_str(row, "action"),
            _row_str(row, "tool_id"),
            _row_str(row, "tool_revision"),
            _row_str(row, "parameters_schema_sha256"),
            _row_str(row, "component_manifest_id"),
            _row_optional_str(row, "model_manifest_id"),
            _row_str(row, "manifest_id"),
        )
        expected = (
            manifest.run_id,
            manifest.execution_manifest_id,
            manifest.case_id,
            manifest.hearing_session_id,
            manifest.acquisition_request_id,
            manifest.action.value,
            manifest.tool_id,
            manifest.tool_revision,
            manifest.parameters_schema_sha256,
            manifest.component_manifest_id,
            manifest.model_manifest_id,
            manifest.manifest_id,
        )
        if (
            indexed != expected
            or manifest.run_id != run_id
            or (manifest.execution_manifest_id != execution_manifest_id)
        ):
            raise RepositoryIntegrityError("tool execution manifest indexes conflict with content")
        request = self._load_acquisition_request(
            connection,
            run_id,
            manifest.acquisition_request_id,
        )
        self._validate_execution_manifest_pin(
            connection,
            request=request,
            execution_manifest=manifest,
        )
        return manifest

    def _insert_acquisition_outputs(
        self,
        connection: sqlite3.Connection,
        execution: AcquisitionExecution,
        *,
        source_pack: EvidencePack,
    ) -> None:
        outputs = execution.output_objects
        for frame in outputs.frames:
            self._insert_acquired_frame(connection, execution.request.run_id, frame)
        for detection in outputs.detections:
            self._insert_acquired_detection(
                connection,
                execution.request.run_id,
                detection,
                execution_manifest=execution.execution_manifest,
            )
        for crop in outputs.crops:
            self._insert_media_asset(
                connection,
                execution.request.run_id,
                crop,
                manifest_id=source_pack.manifest_id,
            )
            self._insert_acquired_crop(
                connection,
                crop,
                execution=execution,
                source_pack=source_pack,
            )

    def _insert_acquired_frame(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        frame: FrameRef,
    ) -> None:
        if frame.content_sha256 is None:
            raise ContractViolation("acquired frame requires decoded RGB8 content authority")
        manifest = self._host._load_run_manifest(connection, run_id)
        stream = next(
            (
                item
                for item in manifest.streams
                if (item.camera_id, item.stream_id) == (frame.camera_id, frame.stream_id)
            ),
            None,
        )
        if stream is None or (
            frame.fps_num != stream.fps_num
            or frame.fps_den != stream.fps_den
            or frame.width != stream.width
            or frame.height != stream.height
            or frame.frame_index >= stream.frame_count
        ):
            raise ManifestMismatch("acquired frame differs from its pinned stream")
        existing = self._host._load_frame(connection, run_id, frame.frame_id)
        if existing is not None:
            if existing != frame:
                raise RepositoryIntegrityError(
                    "acquired frame identity conflicts with persisted content"
                )
            return
        document = _contract_document(frame)
        connection.execute(
            """
            INSERT INTO frames(
                run_id, frame_id, manifest_id, camera_id, stream_id,
                frame_index, fps_num, fps_den, width, height,
                content_sha256, document_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                frame.frame_id,
                manifest.manifest_id,
                frame.camera_id,
                frame.stream_id,
                frame.frame_index,
                frame.fps_num,
                frame.fps_den,
                frame.width,
                frame.height,
                frame.content_sha256,
                document,
                self._canonical_document_sha256(document),
            ),
        )

    def _insert_acquired_detection(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        detection: Detection,
        *,
        execution_manifest: ToolExecutionManifest,
    ) -> None:
        try:
            ArtifactRef(kind=ArtifactKind.DETECTION, artifact_id=detection.detection_id)
        except ValidationError as exc:
            raise ContractViolation("acquired detection identity is invalid") from exc
        if (
            execution_manifest.action != AcquisitionAction.REDETECT_HIGH_RES
            or execution_manifest.model_manifest_id is None
            or detection.model_manifest_id != execution_manifest.model_manifest_id
        ):
            raise ManifestMismatch("acquired detection lacks the execution model authority")
        frame = self._host._load_frame(connection, run_id, detection.frame_id)
        if not isinstance(frame, FrameRef):
            raise EvidenceMissing("acquired detection frame is not registered")
        try:
            FrameBundle(frame=frame, detections=(detection,))
        except ValidationError as exc:
            raise ContractViolation("acquired detection is invalid for its frame") from exc
        existing = self._load_detection_generic(
            connection,
            run_id,
            detection.detection_id,
        )
        if existing is not None:
            if existing != detection:
                raise RepositoryIntegrityError(
                    "acquired detection identity conflicts with persisted content"
                )
            return
        document = _contract_document(detection)
        connection.execute(
            """
            INSERT INTO detections(
                run_id, detection_id, frame_id, manifest_id,
                detector_manifest_id, label,
                document_json, document_sha256, registered_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                detection.detection_id,
                detection.frame_id,
                execution_manifest.manifest_id,
                detection.model_manifest_id,
                detection.label,
                document,
                self._canonical_document_sha256(document),
                _utc_timestamp(self._host._clock),
            ),
        )

    def _load_detection_generic(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        detection_id: str,
    ) -> Detection | None:
        row = connection.execute(
            """
            SELECT detection_id, frame_id, manifest_id,
                   detector_manifest_id, label, document_json, document_sha256
            FROM detections
            WHERE run_id = ? AND detection_id = ?
            """,
            (run_id, detection_id),
        ).fetchone()
        if row is None:
            return None
        raw = _row_str(row, "document_json")
        try:
            detection = Detection.model_validate_json(raw)
        except ValidationError as exc:
            raise RepositoryIntegrityError("stored acquired detection is invalid") from exc
        _verify_document(raw, _row_str(row, "document_sha256"), detection)
        run_manifest = self._host._load_run_manifest(connection, run_id)
        known_models = {model.model_manifest_id for model in run_manifest.models.values()}
        if (
            detection.detection_id != detection_id
            or detection.detection_id != _row_str(row, "detection_id")
            or detection.frame_id != _row_str(row, "frame_id")
            or _row_str(row, "manifest_id") != run_manifest.manifest_id
            or detection.model_manifest_id != _row_str(row, "detector_manifest_id")
            or detection.model_manifest_id not in known_models
            or detection.label != _row_str(row, "label")
        ):
            raise RepositoryIntegrityError(
                "detection indexes or model authority conflict with content"
            )
        frame = self._host._load_frame(connection, run_id, detection.frame_id)
        if not isinstance(frame, FrameRef):
            raise RepositoryIntegrityError("stored detection references a missing frame")
        try:
            FrameBundle(frame=frame, detections=(detection,))
        except ValidationError as exc:
            raise RepositoryIntegrityError("stored detection is invalid for its frame") from exc
        return detection

    def _insert_media_asset(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        crop: Crop,
        *,
        manifest_id: str,
    ) -> None:
        expected = (
            crop.local_path,
            crop.availability.value,
            crop.pixel_sha256,
            crop.output_width,
            crop.output_height,
            crop.size_bytes,
            crop.media_type.value,
            crop.encoding_version,
            manifest_id,
        )
        row = connection.execute(
            """
            SELECT local_path, availability, pixel_sha256, width, height,
                   size_bytes, media_type, encoding_version, manifest_id
            FROM media_assets WHERE run_id = ? AND media_sha256 = ?
            """,
            (run_id, crop.media_sha256),
        ).fetchone()
        if row is not None:
            observed = (
                _row_optional_str(row, "local_path"),
                _row_str(row, "availability"),
                _row_str(row, "pixel_sha256"),
                _row_int(row, "width"),
                _row_int(row, "height"),
                _row_int(row, "size_bytes"),
                _row_str(row, "media_type"),
                _row_str(row, "encoding_version"),
                _row_str(row, "manifest_id"),
            )
            if observed != expected:
                raise RepositoryIntegrityError(
                    "acquired media identity conflicts with persisted metadata"
                )
            return
        path_collision = connection.execute(
            """
            SELECT media_sha256 FROM media_assets
            WHERE run_id = ? AND local_path = ?
            """,
            (run_id, crop.local_path),
        ).fetchone()
        if path_collision is not None:
            raise RepositoryIntegrityError("acquired media locator is already bound to other bytes")
        connection.execute(
            """
            INSERT INTO media_assets(
                run_id, media_sha256, manifest_id, local_path, availability,
                pixel_sha256, width, height, size_bytes, media_type,
                encoding_version, ttl_expires_at, purged_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)
            """,
            (
                run_id,
                crop.media_sha256,
                manifest_id,
                crop.local_path,
                crop.availability.value,
                crop.pixel_sha256,
                crop.output_width,
                crop.output_height,
                crop.size_bytes,
                crop.media_type.value,
                crop.encoding_version,
            ),
        )

    def _insert_acquired_crop(
        self,
        connection: sqlite3.Connection,
        crop: Crop,
        *,
        execution: AcquisitionExecution,
        source_pack: EvidencePack,
    ) -> None:
        request = execution.request
        manifest = execution.execution_manifest
        row = connection.execute(
            """
            SELECT crop_id FROM m4_acquired_crops
            WHERE run_id = ? AND acquisition_request_id = ?
            """,
            (request.run_id, request.request_id),
        ).fetchone()
        if row is not None:
            stored = self._load_acquired_crop(
                connection,
                request.run_id,
                _row_str(row, "crop_id"),
            )
            if stored != crop:
                raise HearingPersistenceConflict(
                    "acquired crop identity conflicts with persisted content"
                )
            return
        document = _contract_document(crop)
        connection.execute(
            """
            INSERT INTO m4_acquired_crops(
                run_id, crop_id, case_id, hearing_id, acquisition_request_id,
                execution_manifest_id, frame_id, media_sha256,
                source_media_sha256, pixel_sha256, source_pack_id,
                source_pack_version, manifest_id, crop_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request.run_id,
                crop.crop_id,
                request.case_id,
                request.hearing_session_id,
                request.request_id,
                manifest.execution_manifest_id,
                crop.frame_id,
                crop.media_sha256,
                crop.source_media_sha256,
                crop.pixel_sha256,
                source_pack.pack_id,
                source_pack.version,
                request.manifest_id,
                document,
                self._canonical_document_sha256(document),
            ),
        )

    def _load_acquired_crop(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        crop_id: str,
    ) -> Crop:
        row = connection.execute(
            """
            SELECT * FROM m4_acquired_crops
            WHERE run_id = ? AND crop_id = ?
            """,
            (run_id, crop_id),
        ).fetchone()
        if row is None:
            raise EvidenceMissing(f"unknown acquired crop in run {run_id}: {crop_id}")
        raw = _row_str(row, "crop_json")
        try:
            crop = Crop.model_validate_json(raw)
        except ValidationError as exc:
            raise RepositoryIntegrityError("stored acquired crop is invalid") from exc
        _verify_document(raw, _row_str(row, "document_sha256"), crop)
        if (
            crop.crop_id != crop_id
            or crop.crop_id != _row_str(row, "crop_id")
            or crop.frame_id != _row_str(row, "frame_id")
            or crop.media_sha256 != _row_str(row, "media_sha256")
            or crop.source_media_sha256 != _row_str(row, "source_media_sha256")
            or crop.pixel_sha256 != _row_str(row, "pixel_sha256")
        ):
            raise RepositoryIntegrityError("acquired crop indexes conflict with canonical content")
        request = self._load_acquisition_request(
            connection,
            run_id,
            _row_str(row, "acquisition_request_id"),
        )
        manifest = self._load_tool_execution_manifest(
            connection,
            run_id,
            _row_str(row, "execution_manifest_id"),
        )
        if (
            request.action != AcquisitionAction.RECROP
            or request.case_id != _row_str(row, "case_id")
            or request.hearing_session_id != _row_str(row, "hearing_id")
            or request.current_evidence_pack_id != _row_str(row, "source_pack_id")
            or request.current_evidence_pack_version != _row_int(row, "source_pack_version")
            or request.manifest_id != _row_str(row, "manifest_id")
            or manifest.acquisition_request_id != request.request_id
        ):
            raise RepositoryIntegrityError(
                "acquired crop conflicts with request or execution authority"
            )
        media = connection.execute(
            """
            SELECT manifest_id, local_path, availability, pixel_sha256,
                   width, height, size_bytes, media_type, encoding_version
            FROM media_assets WHERE run_id = ? AND media_sha256 = ?
            """,
            (run_id, crop.media_sha256),
        ).fetchone()
        if media is None or (
            _row_str(media, "manifest_id") != request.manifest_id
            or _row_optional_str(media, "local_path") != crop.local_path
            or _row_str(media, "availability") != crop.availability.value
            or _row_str(media, "pixel_sha256") != crop.pixel_sha256
            or _row_int(media, "width") != crop.output_width
            or _row_int(media, "height") != crop.output_height
            or _row_int(media, "size_bytes") != crop.size_bytes
            or _row_str(media, "media_type") != crop.media_type.value
            or _row_str(media, "encoding_version") != crop.encoding_version
        ):
            raise RepositoryIntegrityError(
                "acquired crop media metadata conflicts with canonical content"
            )
        return crop

    def _close_acquisition_draft(
        self,
        draft: EvidencePackDraft,
        *,
        physical_crops: tuple[Crop, ...],
    ) -> EvidencePack:
        """Close an M4 successor without consulting M2's semantic parser."""

        crop_ids = tuple(crop.crop_id for crop in physical_crops)
        if len(crop_ids) != len(set(crop_ids)) or crop_ids != tuple(sorted(crop_ids)):
            raise ContractViolation(
                "acquisition physical crops must be unique and use stable order"
            )
        defects: list[ClosureDefect] = []
        verifier = self._host._verifier
        if physical_crops and verifier is None:
            raise EvidenceMissing("physical crop verification is required for acquisition")
        if verifier is not None:
            for crop in physical_crops:
                raw = verifier.verify_crop(crop)
                verification = ArtifactVerification.model_validate(raw.model_dump(mode="json"))
                expected_refs = {
                    (ArtifactKind.CROP, crop.crop_id),
                    (ArtifactKind.MEDIA, crop.media_sha256),
                }
                if (
                    (verification.artifact_ref.kind, verification.artifact_ref.artifact_id)
                    not in expected_refs
                    or verification.expected_source_pixel_sha256 != crop.source_media_sha256
                    or verification.expected_output_pixel_sha256 != crop.pixel_sha256
                    or verification.expected_media_sha256 != crop.media_sha256
                    or verification.expected_width != crop.output_width
                    or verification.expected_height != crop.output_height
                    or verification.expected_size_bytes != crop.size_bytes
                    or verification.media_type != crop.media_type
                    or verification.availability != crop.availability
                ):
                    raise RepositoryIntegrityError(
                        "physical verifier returned expectations for another acquisition crop"
                    )
                defect = self._acquisition_verification_defect(crop, verification)
                if defect is not None:
                    defects.append(defect)
        ordered_defects = tuple(sorted(set(defects), key=lambda item: item.sort_key))
        report = ClosureReport(
            run_id=draft.run_id,
            root_ref=ArtifactRef(kind=ArtifactKind.CASE, artifact_id=draft.case_id),
            manifest_id=draft.manifest_id,
            input_sha256=draft.closure_input_sha256,
            checked_refs=draft.expected_closure_refs(),
            defects=ordered_defects,
        )
        if not report.passed:
            raise CreationClosureFailed(tuple(defect.code for defect in report.defects))
        payload = draft.model_dump(mode="json", exclude_computed_fields=True)
        payload["closure_report"] = report.model_dump(mode="json")
        try:
            return EvidencePack.model_validate(payload)
        except ValidationError as exc:
            raise ContractViolation("acquisition successor cannot be closed") from exc

    @staticmethod
    def _acquisition_verification_defect(
        crop: Crop,
        verification: ArtifactVerification,
    ) -> ClosureDefect | None:
        if verification.status in {
            VerificationStatus.VERIFIED,
            VerificationStatus.CURRENT_MEDIA_VERIFIED,
        }:
            return None
        ref = ArtifactRef(kind=ArtifactKind.CROP, artifact_id=crop.crop_id)
        if verification.status == VerificationStatus.SOURCE_HASH_MISMATCH:
            assert verification.actual_source_pixel_sha256 is not None
            return ClosureDefect(
                code=ClosureDefectCode.SOURCE_HASH_MISMATCH,
                artifact_ref=ref,
                expected_sha256=verification.expected_source_pixel_sha256,
                actual_sha256=verification.actual_source_pixel_sha256,
            )
        if verification.status == VerificationStatus.PIXEL_HASH_MISMATCH:
            assert verification.actual_output_pixel_sha256 is not None
            return ClosureDefect(
                code=ClosureDefectCode.PIXEL_HASH_MISMATCH,
                artifact_ref=ref,
                expected_sha256=verification.expected_output_pixel_sha256,
                actual_sha256=verification.actual_output_pixel_sha256,
            )
        if verification.status == VerificationStatus.MEDIA_HASH_MISMATCH:
            assert verification.actual_media_sha256 is not None
            return ClosureDefect(
                code=ClosureDefectCode.MEDIA_HASH_MISMATCH,
                artifact_ref=ref,
                expected_sha256=verification.expected_media_sha256,
                actual_sha256=verification.actual_media_sha256,
            )
        if verification.status == VerificationStatus.SIZE_MISMATCH:
            assert verification.actual_size_bytes is not None
            return ClosureDefect(
                code=ClosureDefectCode.MEDIA_SIZE_MISMATCH,
                artifact_ref=ref,
                expected_size_bytes=verification.expected_size_bytes,
                actual_size_bytes=verification.actual_size_bytes,
            )
        if verification.status == VerificationStatus.DIMENSION_MISMATCH:
            assert verification.actual_width is not None
            assert verification.actual_height is not None
            return ClosureDefect(
                code=ClosureDefectCode.MEDIA_DIMENSION_MISMATCH,
                artifact_ref=ref,
                expected_width=verification.expected_width,
                actual_width=verification.actual_width,
                expected_height=verification.expected_height,
                actual_height=verification.actual_height,
            )
        if verification.status == VerificationStatus.PRIVACY_POLICY_VIOLATION:
            assert verification.reason_code is not None
            return ClosureDefect(
                code=ClosureDefectCode.PRIVACY_POLICY_VIOLATION,
                artifact_ref=ref,
                reason_code=verification.reason_code,
            )
        status_codes = {
            VerificationStatus.PATH_BOUNDARY_VIOLATION: (ClosureDefectCode.PATH_BOUNDARY_VIOLATION),
            VerificationStatus.UNSAFE_LINK: ClosureDefectCode.UNSAFE_LINK,
            VerificationStatus.NOT_REGULAR_FILE: ClosureDefectCode.NOT_REGULAR_FILE,
            VerificationStatus.PURGED_BY_RETENTION: (ClosureDefectCode.MEDIA_PURGED_BY_RETENTION),
        }
        return ClosureDefect(
            code=status_codes.get(verification.status, ClosureDefectCode.MEDIA_MISSING),
            artifact_ref=ref,
            reason_code=verification.status.value,
        )

    def _insert_acquisition_pack(
        self,
        connection: sqlite3.Connection,
        pack: EvidencePack,
        *,
        created_audit_sequence: int,
    ) -> None:
        next_version_row = connection.execute(
            """
            SELECT COALESCE(MAX(version), 0) + 1 AS next_version
            FROM evidence_packs WHERE run_id = ? AND case_id = ?
            """,
            (pack.run_id, pack.case_id),
        ).fetchone()
        if next_version_row is None or _row_int(next_version_row, "next_version") != pack.version:
            raise ConcurrentModification(
                "next evidence pack version changed before acquisition publication"
            )
        collision = connection.execute(
            """
            SELECT pack_id FROM evidence_packs
            WHERE run_id = ? AND (pack_id = ? OR (case_id = ? AND version = ?))
            """,
            (pack.run_id, pack.pack_id, pack.case_id, pack.version),
        ).fetchall()
        if collision:
            raise HearingPersistenceConflict(
                "acquisition pack identity collides with persisted authority"
            )
        document = _contract_document(pack)
        connection.execute(
            """
            INSERT INTO evidence_packs(
                run_id, pack_id, case_id, manifest_id, version, complete,
                pack_input_sha256, closure_input_sha256,
                pack_json, document_sha256, created_audit_sequence
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                pack.run_id,
                pack.pack_id,
                pack.case_id,
                pack.manifest_id,
                pack.version,
                int(pack.complete),
                pack.pack_input_sha256,
                pack.closure_input_sha256,
                document,
                self._canonical_document_sha256(document),
                created_audit_sequence,
            ),
        )
        for crop in pack.crops:
            self._insert_media_asset(
                connection,
                pack.run_id,
                crop,
                manifest_id=pack.manifest_id,
            )
        for role, crops in (
            ("panorama", pack.panorama_crops),
            ("subject", pack.subject_crops),
            ("focus", pack.focus_crops),
            ("temporal", pack.temporal_crops),
        ):
            for ordinal, crop in enumerate(crops):
                crop_document = _contract_document(crop)
                connection.execute(
                    """
                    INSERT INTO evidence_pack_crops(
                        run_id, pack_id, crop_id, media_sha256,
                        role, ordinal, crop_json, document_sha256
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        pack.run_id,
                        pack.pack_id,
                        crop.crop_id,
                        crop.media_sha256,
                        role,
                        ordinal,
                        crop_document,
                        self._canonical_document_sha256(crop_document),
                    ),
                )

    def _insert_tool_execution_receipt(
        self,
        connection: sqlite3.Connection,
        receipt: ToolExecutionReceipt,
        *,
        cycle_scope_id: str,
        cycle_scope_sha256: str,
    ) -> None:
        request = receipt.request
        document = _contract_document(receipt)
        connection.execute(
            """
            INSERT INTO m4_tool_execution_receipts(
                run_id, receipt_id, acquisition_request_id, hearing_id,
                cycle_scope_id, cycle_scope_sha256, case_id, action,
                execution_manifest_id, tool_result_id,
                resulting_pack_id, resulting_pack_version,
                receipt_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request.run_id,
                receipt.receipt_id,
                request.request_id,
                request.hearing_session_id,
                cycle_scope_id,
                cycle_scope_sha256,
                request.case_id,
                request.action.value,
                receipt.execution_manifest.execution_manifest_id,
                receipt.tool_result.tool_result_id,
                receipt.resulting_evidence_pack_id,
                receipt.resulting_evidence_pack_version,
                document,
                self._canonical_document_sha256(document),
            ),
        )

    def _load_tool_execution_receipt(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        receipt_id: str,
    ) -> ToolExecutionReceipt:
        row = connection.execute(
            """
            SELECT * FROM m4_tool_execution_receipts
            WHERE run_id = ? AND receipt_id = ?
            """,
            (run_id, receipt_id),
        ).fetchone()
        if row is None:
            raise EvidenceMissing(f"unknown tool receipt in run {run_id}: {receipt_id}")
        raw = _row_str(row, "receipt_json")
        try:
            receipt = ToolExecutionReceipt.model_validate_json(raw)
        except ValidationError as exc:
            raise RepositoryIntegrityError("stored tool execution receipt is invalid") from exc
        _verify_document(raw, _row_str(row, "document_sha256"), receipt)
        request = receipt.request
        indexed = (
            _row_str(row, "run_id"),
            _row_str(row, "receipt_id"),
            _row_str(row, "acquisition_request_id"),
            _row_str(row, "hearing_id"),
            _row_str(row, "case_id"),
            _row_str(row, "action"),
            _row_str(row, "execution_manifest_id"),
            _row_str(row, "tool_result_id"),
            _row_str(row, "resulting_pack_id"),
            _row_int(row, "resulting_pack_version"),
        )
        expected = (
            request.run_id,
            receipt.receipt_id,
            request.request_id,
            request.hearing_session_id,
            request.case_id,
            request.action.value,
            receipt.execution_manifest.execution_manifest_id,
            receipt.tool_result.tool_result_id,
            receipt.resulting_evidence_pack_id,
            receipt.resulting_evidence_pack_version,
        )
        if indexed != expected or request.run_id != run_id or receipt.receipt_id != receipt_id:
            raise RepositoryIntegrityError("tool receipt indexes conflict with content")
        if self._load_acquisition_request(connection, run_id, request.request_id) != request:
            raise RepositoryIntegrityError("tool receipt request differs from durable authority")
        if (
            self._load_tool_execution_manifest(
                connection,
                run_id,
                receipt.execution_manifest.execution_manifest_id,
            )
            != receipt.execution_manifest
        ):
            raise RepositoryIntegrityError("tool receipt manifest differs from durable authority")
        cycle_scope_id, cycle_scope_sha256 = self._acquisition_cycle_scope_id(
            connection,
            request,
        )
        if (
            _row_str(row, "cycle_scope_id") != cycle_scope_id
            or _row_str(row, "cycle_scope_sha256") != cycle_scope_sha256
        ):
            raise RepositoryIntegrityError("tool receipt cycle scope is inconsistent")
        return receipt

    def _insert_evidence_pack_derivation(
        self,
        connection: sqlite3.Connection,
        derivation: EvidencePackDerivation,
    ) -> None:
        document = _contract_document(derivation)
        connection.execute(
            """
            INSERT INTO m4_evidence_pack_derivations(
                run_id, derivation_id, hearing_id,
                source_cycle_scope_id, source_cycle_scope_sha256, case_id,
                previous_pack_id, previous_pack_version,
                new_pack_id, new_pack_version, tool_receipt_id,
                manifest_id, derivation_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                derivation.run_id,
                derivation.derivation_id,
                derivation.hearing_session_id,
                derivation.source_cycle_scope_id,
                derivation.source_cycle_scope_sha256,
                derivation.case_id,
                derivation.previous_evidence_pack_id,
                derivation.previous_evidence_pack_version,
                derivation.new_evidence_pack_id,
                derivation.new_evidence_pack_version,
                derivation.tool_execution_receipt_id,
                derivation.manifest_id,
                document,
                self._canonical_document_sha256(document),
            ),
        )

    def _load_evidence_pack_derivation(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        derivation_id: str,
    ) -> EvidencePackDerivation:
        row = connection.execute(
            """
            SELECT * FROM m4_evidence_pack_derivations
            WHERE run_id = ? AND derivation_id = ?
            """,
            (run_id, derivation_id),
        ).fetchone()
        if row is None:
            raise EvidenceMissing(
                f"unknown evidence pack derivation in run {run_id}: {derivation_id}"
            )
        raw = _row_str(row, "derivation_json")
        try:
            derivation = EvidencePackDerivation.model_validate_json(raw)
        except ValidationError as exc:
            raise RepositoryIntegrityError("stored pack derivation is invalid") from exc
        _verify_document(raw, _row_str(row, "document_sha256"), derivation)
        indexed = (
            _row_str(row, "run_id"),
            _row_str(row, "derivation_id"),
            _row_str(row, "hearing_id"),
            _row_str(row, "source_cycle_scope_id"),
            _row_str(row, "source_cycle_scope_sha256"),
            _row_str(row, "case_id"),
            _row_str(row, "previous_pack_id"),
            _row_int(row, "previous_pack_version"),
            _row_str(row, "new_pack_id"),
            _row_int(row, "new_pack_version"),
            _row_str(row, "tool_receipt_id"),
            _row_str(row, "manifest_id"),
        )
        expected = (
            derivation.run_id,
            derivation.derivation_id,
            derivation.hearing_session_id,
            derivation.source_cycle_scope_id,
            derivation.source_cycle_scope_sha256,
            derivation.case_id,
            derivation.previous_evidence_pack_id,
            derivation.previous_evidence_pack_version,
            derivation.new_evidence_pack_id,
            derivation.new_evidence_pack_version,
            derivation.tool_execution_receipt_id,
            derivation.manifest_id,
        )
        if (
            indexed != expected
            or derivation.run_id != run_id
            or (derivation.derivation_id != derivation_id)
        ):
            raise RepositoryIntegrityError("pack derivation indexes conflict with content")
        return derivation

    def _replay_acquisition_successor(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        expected_case_revision: int,
        expected_audit_head: AuditHead,
        execution: AcquisitionExecution,
        receipt_id: str,
    ) -> AcquisitionPublishResult:
        receipt = self._load_tool_execution_receipt(connection, run_id, receipt_id)
        if (
            receipt.request != execution.request
            or receipt.execution_manifest != execution.execution_manifest
            or receipt.tool_result != execution.tool_result
        ):
            raise HearingPersistenceConflict(
                "acquisition retry conflicts with the persisted execution closure"
            )
        derivation_row = connection.execute(
            """
            SELECT derivation_id
            FROM m4_evidence_pack_derivations
            WHERE run_id = ? AND tool_receipt_id = ?
            """,
            (run_id, receipt_id),
        ).fetchone()
        if derivation_row is None:
            raise RepositoryIntegrityError(
                "persisted tool receipt lacks its evidence-pack derivation"
            )
        derivation = self._load_evidence_pack_derivation(
            connection,
            run_id,
            _row_str(derivation_row, "derivation_id"),
        )
        if (
            derivation.previous_evidence_pack_id != execution.request.current_evidence_pack_id
            or derivation.previous_evidence_pack_version
            != execution.request.current_evidence_pack_version
            or derivation.new_evidence_pack_id != receipt.resulting_evidence_pack_id
            or derivation.new_evidence_pack_version != receipt.resulting_evidence_pack_version
            or derivation.tool_execution_receipt_id != receipt.receipt_id
        ):
            raise RepositoryIntegrityError(
                "persisted pack derivation conflicts with its tool receipt"
            )
        authority = self._load_hearing_evidence_authority(
            connection,
            run_id=run_id,
            hearing_id=execution.request.hearing_session_id,
            current_pack_id=receipt.resulting_evidence_pack_id,
        )
        if not authority.receipts or authority.receipts[-1] != receipt:
            raise HearingPersistenceConflict(
                "acquisition retry no longer identifies the hearing pack head"
            )
        output_objects = self._loaded_objects_for_refs(
            authority.loaded_objects,
            frozenset(receipt.tool_result.output_refs),
        )
        if output_objects != execution.output_objects:
            raise HearingPersistenceConflict(
                "acquisition retry outputs conflict with persisted typed objects"
            )
        predecessor = self._host._load_pack(
            connection,
            run_id,
            receipt.request.current_evidence_pack_id,
        )
        if not isinstance(predecessor, EvidencePack):
            raise RepositoryIntegrityError("acquisition predecessor pack is invalid")
        prior_receipts = authority.receipts[:-1]
        predecessor_objects = self._loaded_objects_for_refs(
            authority.loaded_objects,
            frozenset(predecessor.expected_closure_refs()),
        )
        try:
            draft = derive_evidence_pack_successor(
                predecessor,
                execution,
                current_receipts=prior_receipts,
                current_loaded_objects=predecessor_objects,
            )
        except (EvidenceAuthorityError, AcquisitionAuthorityError) as exc:
            raise RepositoryIntegrityError(
                "persisted acquisition retry cannot reconstruct its successor"
            ) from exc
        if draft.model_dump(mode="json") != authority.pack.model_dump(
            mode="json",
            exclude={"closure_report"},
        ):
            raise HearingPersistenceConflict(
                "acquisition retry derives different successor content"
            )
        committed = self._load_case_revision(
            connection,
            run_id,
            receipt.request.case_id,
            expected_case_revision + 1,
        )
        if (
            committed.case.status != CaseStatus.DELIBERATING
            or not committed.case.evidence_packs
            or committed.case.evidence_packs[-1] != authority.pack
            or not committed.case.timeline
            or committed.case.timeline[-1].object_ref != receipt.receipt_id
        ):
            raise HearingPersistenceConflict(
                "persisted acquisition roots lack the expected Case transition"
            )
        self._verify_transition_audit(
            connection,
            run_id=run_id,
            audit_sequence=expected_audit_head.sequence + 1,
            expected_head=expected_audit_head,
            object_id=receipt.request.case_id,
            object_kind=ArtifactKind.CASE,
            action=AuditAction.EVIDENCE_PACK_PUBLISHED,
        )
        return AcquisitionPublishResult(
            case=committed,
            pack=authority.pack,
            receipt=receipt,
            created=False,
        )

    @staticmethod
    def _loaded_objects_for_refs(
        loaded: LoadedEvidenceObjects,
        refs: frozenset[ArtifactRef],
    ) -> LoadedEvidenceObjects:
        return LoadedEvidenceObjects(
            frames=tuple(
                frame
                for frame in loaded.frames
                if ArtifactRef(kind=ArtifactKind.FRAME, artifact_id=frame.frame_id) in refs
            ),
            crops=tuple(
                crop
                for crop in loaded.crops
                if ArtifactRef(kind=ArtifactKind.CROP, artifact_id=crop.crop_id) in refs
            ),
            objective_facts=tuple(
                fact
                for fact in loaded.objective_facts
                if ArtifactRef(kind=ArtifactKind.OBJECTIVE_FACT, artifact_id=fact.fact_id) in refs
            ),
            detections=tuple(
                detection
                for detection in loaded.detections
                if ArtifactRef(
                    kind=ArtifactKind.DETECTION,
                    artifact_id=detection.detection_id,
                )
                in refs
            ),
        )

    def load_hearing_evidence_authority(
        self,
        run_id: str,
        hearing_id: str,
        current_pack_id: str,
    ) -> EvidenceAuthority:
        require_reference_token(run_id, "hearing repository run_id")
        require_reference_token(hearing_id, "hearing session ID")
        require_reference_token(current_pack_id, "hearing evidence pack ID")
        connection = self._host._connection(require_hardening=True, require_m4=True)
        try:
            return self._load_hearing_evidence_authority(
                connection,
                run_id=run_id,
                hearing_id=hearing_id,
                current_pack_id=current_pack_id,
            )
        finally:
            connection.close()

    def _load_hearing_evidence_authority(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        hearing_id: str,
        current_pack_id: str,
    ) -> EvidenceAuthority:
        """Reconstruct the exact receipt/object lineage from one SQLite snapshot."""

        session = self._load_hearing_session(connection, run_id, hearing_id)
        initial = self._host._load_pack(
            connection,
            run_id,
            session.initial_evidence_pack_id,
        )
        if not isinstance(initial, EvidencePack) or (
            initial.case_id != session.case_id
            or initial.version != session.initial_evidence_pack_version
            or initial.manifest_id != session.manifest_id
        ):
            raise RepositoryIntegrityError(
                "hearing initial pack differs from immutable session authority"
            )
        rows = connection.execute(
            """
            SELECT derivation_id
            FROM m4_evidence_pack_derivations
            WHERE run_id = ? AND hearing_id = ?
            ORDER BY new_pack_version, derivation_id
            """,
            (run_id, hearing_id),
        ).fetchall()
        derivations = tuple(
            self._load_evidence_pack_derivation(
                connection,
                run_id,
                _row_str(row, "derivation_id"),
            )
            for row in rows
        )
        receipts: list[ToolExecutionReceipt] = []
        packs: list[EvidencePack] = [initial]
        cursor = initial
        for derivation in derivations:
            if (
                derivation.hearing_session_id != hearing_id
                or derivation.case_id != session.case_id
                or derivation.manifest_id != session.manifest_id
                or derivation.previous_evidence_pack_id != cursor.pack_id
                or derivation.previous_evidence_pack_version != cursor.version
            ):
                raise RepositoryIntegrityError(
                    "hearing pack derivation history is forked or discontinuous"
                )
            receipt = self._load_tool_execution_receipt(
                connection,
                run_id,
                derivation.tool_execution_receipt_id,
            )
            if (
                receipt.request.hearing_session_id != hearing_id
                or receipt.request.case_id != session.case_id
                or receipt.request.current_evidence_pack_id != cursor.pack_id
                or receipt.request.current_evidence_pack_version != cursor.version
                or receipt.resulting_evidence_pack_id != derivation.new_evidence_pack_id
                or receipt.resulting_evidence_pack_version != derivation.new_evidence_pack_version
            ):
                raise RepositoryIntegrityError(
                    "hearing tool receipt conflicts with its pack derivation"
                )
            successor = self._host._load_pack(
                connection,
                run_id,
                derivation.new_evidence_pack_id,
            )
            if not isinstance(successor, EvidencePack) or (
                successor.case_id != session.case_id
                or successor.version != derivation.new_evidence_pack_version
                or successor.manifest_id != session.manifest_id
            ):
                raise RepositoryIntegrityError(
                    "derived hearing pack conflicts with immutable pack authority"
                )
            receipts.append(receipt)
            packs.append(successor)
            cursor = successor
        receipt_count_row = connection.execute(
            """
            SELECT COUNT(*) AS receipt_count
            FROM m4_tool_execution_receipts
            WHERE run_id = ? AND hearing_id = ?
            """,
            (run_id, hearing_id),
        ).fetchone()
        if receipt_count_row is None or _row_int(receipt_count_row, "receipt_count") != len(
            receipts
        ):
            raise RepositoryIntegrityError("hearing has an orphan or multiply-derived tool receipt")
        if cursor.pack_id != current_pack_id:
            raise RepositoryIntegrityError(
                "requested hearing pack is not the unique acquisition head"
            )

        final_refs = frozenset(cursor.expected_closure_refs())
        frame_refs = tuple(
            sorted(
                (ref for ref in final_refs if ref.kind == ArtifactKind.FRAME),
                key=lambda ref: ref.sort_key,
            )
        )
        frames: list[FrameRef] = []
        for ref in frame_refs:
            frame = self._host._load_frame(connection, run_id, ref.artifact_id)
            if not isinstance(frame, FrameRef):
                raise RepositoryIntegrityError(
                    "hearing pack closure references a missing frame object"
                )
            frames.append(frame)

        crop_by_id = {crop.crop_id: crop for crop in cursor.crops}
        for ref in sorted(
            (ref for ref in final_refs if ref.kind == ArtifactKind.CROP),
            key=lambda item: item.sort_key,
        ):
            if ref.artifact_id not in crop_by_id:
                crop_by_id[ref.artifact_id] = self._load_acquired_crop(
                    connection,
                    run_id,
                    ref.artifact_id,
                )
        fact_by_id = {fact.fact_id: fact for fact in cursor.objective_facts}
        expected_fact_ids = {
            ref.artifact_id for ref in final_refs if ref.kind == ArtifactKind.OBJECTIVE_FACT
        }
        if set(fact_by_id) != expected_fact_ids:
            raise RepositoryIntegrityError(
                "hearing pack objective-fact closure is incomplete or excessive"
            )
        detections: list[Detection] = []
        for ref in sorted(
            (ref for ref in final_refs if ref.kind == ArtifactKind.DETECTION),
            key=lambda item: item.sort_key,
        ):
            detection = self._load_detection_generic(
                connection,
                run_id,
                ref.artifact_id,
            )
            if detection is None:
                raise RepositoryIntegrityError(
                    "hearing pack closure references a missing detection object"
                )
            detections.append(detection)
        loaded = LoadedEvidenceObjects(
            frames=tuple(frames),
            crops=tuple(crop_by_id[key] for key in sorted(crop_by_id)),
            objective_facts=tuple(fact_by_id[key] for key in sorted(fact_by_id)),
            detections=tuple(detections),
        )
        for index, (previous, successor, receipt) in enumerate(
            zip(packs[:-1], packs[1:], receipts, strict=True)
        ):
            prior_receipts = tuple(receipts[:index])
            successor_receipts = tuple(receipts[: index + 1])
            previous_objects = self._loaded_objects_for_refs(
                loaded,
                frozenset(previous.expected_closure_refs()),
            )
            successor_objects = self._loaded_objects_for_refs(
                loaded,
                frozenset(successor.expected_closure_refs()),
            )
            try:
                derive_evidence_authority(previous, prior_receipts, previous_objects)
                validate_evidence_pack_successor(
                    previous,
                    successor,
                    receipt,
                    current_receipts=prior_receipts,
                    loaded_objects=successor_objects,
                )
                derive_evidence_authority(
                    successor,
                    successor_receipts,
                    successor_objects,
                )
            except (EvidenceAuthorityError, EvidencePackSuccessorError) as exc:
                raise RepositoryIntegrityError(
                    "hearing acquisition lineage failed trusted reconstruction"
                ) from exc
        try:
            return derive_evidence_authority(cursor, tuple(receipts), loaded)
        except EvidenceAuthorityError as exc:
            raise RepositoryIntegrityError(
                "hearing evidence authority failed trusted reconstruction"
            ) from exc

    def _load_pack_closure_authority(
        self,
        connection: sqlite3.Connection,
        draft: EvidencePackDraft,
    ) -> tuple[frozenset[str], frozenset[str]]:
        """Prove the M4-only manifest and predecessor refs carried by one pack.

        An ID is not authority.  The current pack must be the unique head of a
        completely reconstructed hearing lineage; every accepted execution
        manifest and predecessor pack must then be bound by the exact typed
        request, tool result, receipt, and adjacent derivation in that lineage.
        """

        if not draft.tool_results:
            return frozenset(), frozenset()
        installed = connection.execute(
            """
            SELECT 1
            FROM sqlite_master
            WHERE type = 'table' AND name = 'm4_evidence_pack_derivations'
            """
        ).fetchone()
        if installed is None:
            return frozenset(), frozenset()
        rows = connection.execute(
            """
            SELECT derivation_id, hearing_id
            FROM m4_evidence_pack_derivations
            WHERE run_id = ? AND case_id = ?
              AND new_pack_id = ? AND new_pack_version = ?
            ORDER BY derivation_id
            """,
            (draft.run_id, draft.case_id, draft.pack_id, draft.version),
        ).fetchall()
        if not rows:
            return frozenset(), frozenset()
        if len(rows) != 1:
            raise RepositoryIntegrityError(
                "M4 pack closure has multiple current derivation authorities"
            )
        derivation = self._load_evidence_pack_derivation(
            connection,
            draft.run_id,
            _row_str(rows[0], "derivation_id"),
        )
        hearing_id = _row_str(rows[0], "hearing_id")
        if (
            derivation.hearing_session_id != hearing_id
            or derivation.case_id != draft.case_id
            or derivation.new_evidence_pack_id != draft.pack_id
            or derivation.new_evidence_pack_version != draft.version
            or derivation.manifest_id != draft.manifest_id
        ):
            raise RepositoryIntegrityError(
                "M4 pack closure derivation conflicts with the current pack"
            )
        authority = self._load_hearing_evidence_authority(
            connection,
            run_id=draft.run_id,
            hearing_id=hearing_id,
            current_pack_id=draft.pack_id,
        )
        if draft.model_dump(mode="json") != authority.pack.model_dump(
            mode="json",
            exclude={"closure_report"},
        ):
            raise RepositoryIntegrityError(
                "M4 pack closure draft differs from the reconstructed pack head"
            )

        receipts_by_result: dict[str, ToolExecutionReceipt] = {}
        for receipt in authority.receipts:
            result_id = receipt.tool_result.tool_result_id
            if result_id in receipts_by_result:
                raise RepositoryIntegrityError(
                    "M4 pack closure has multiply-receipted tool results"
                )
            receipts_by_result[result_id] = receipt
        results_by_id = {result.tool_result_id: result for result in draft.tool_results}
        if set(receipts_by_result) != set(results_by_id):
            raise RepositoryIntegrityError(
                "M4 pack closure tool results differ from its receipt lineage"
            )

        execution_manifest_ids: set[str] = set()
        predecessor_pack_ids: set[str] = set()
        for result_id, result in results_by_id.items():
            receipt = receipts_by_result[result_id]
            request = receipt.request
            if (
                receipt.tool_result != result
                or request.run_id != draft.run_id
                or request.case_id != draft.case_id
                or request.manifest_id != draft.manifest_id
                or receipt.execution_manifest.execution_manifest_id != result.execution_manifest_id
            ):
                raise RepositoryIntegrityError(
                    "M4 pack closure result conflicts with its request or manifest"
                )
            pack_inputs = {
                ref.artifact_id
                for ref in result.input_refs
                if ref.kind == ArtifactKind.EVIDENCE_PACK
            }
            if pack_inputs != {request.current_evidence_pack_id}:
                raise RepositoryIntegrityError(
                    "M4 pack closure result lacks its exact predecessor input"
                )
            execution_manifest_ids.add(result.execution_manifest_id)
            predecessor_pack_ids.add(request.current_evidence_pack_id)
        return frozenset(execution_manifest_ids), frozenset(predecessor_pack_ids)

    def load_hearing_session(self, run_id: str, hearing_id: str) -> HearingSession:
        require_reference_token(run_id, "hearing repository run_id")
        require_reference_token(hearing_id, "hearing session ID")
        connection = self._host._connection(require_hardening=True, require_m4=True)
        try:
            return self._load_hearing_session(connection, run_id, hearing_id)
        finally:
            connection.close()

    def load_active_hearing(self, run_id: str, case_id: str) -> HearingSession | None:
        """Return the unique non-terminal hearing for a Case, failing on a split head."""

        require_reference_token(run_id, "hearing repository run_id")
        require_reference_token(case_id, "hearing Case ID")
        connection = self._host._connection(require_hardening=True, require_m4=True)
        try:
            rows = connection.execute(
                """
                SELECT hearing_id
                FROM m4_hearings
                WHERE run_id = ? AND case_id = ?
                ORDER BY hearing_id
                """,
                (run_id, case_id),
            ).fetchall()
            active: list[HearingSession] = []
            for row in rows:
                hearing_id = _row_str(row, "hearing_id")
                session = self._load_hearing_session(connection, run_id, hearing_id)
                checkpoints = self._list_hearing_checkpoints(connection, run_id, hearing_id)
                if not checkpoints:
                    raise RepositoryIntegrityError("persisted hearing has no checkpoint head")
                if checkpoints[-1].phase not in {
                    HearingCheckpointPhase.COMPLETE,
                    HearingCheckpointPhase.HUMAN_REVIEW,
                }:
                    active.append(session)
            if len(active) > 1:
                raise RepositoryIntegrityError("Case has multiple active hearing heads")
            return active[0] if active else None
        finally:
            connection.close()

    def load_latest_hearing_checkpoint(
        self,
        run_id: str,
        hearing_id: str,
    ) -> HearingCheckpoint:
        require_reference_token(run_id, "hearing repository run_id")
        require_reference_token(hearing_id, "hearing session ID")
        connection = self._host._connection(require_hardening=True, require_m4=True)
        try:
            return self._load_latest_hearing_checkpoint(connection, run_id, hearing_id)
        finally:
            connection.close()

    def list_hearing_cycles(
        self,
        run_id: str,
        hearing_id: str,
    ) -> tuple[HearingCycleScope, ...]:
        require_reference_token(run_id, "hearing repository run_id")
        require_reference_token(hearing_id, "hearing session ID")
        connection = self._host._connection(require_hardening=True, require_m4=True)
        try:
            self._load_hearing_session(connection, run_id, hearing_id)
            rows = connection.execute(
                """
                SELECT cycle_id FROM m4_hearing_cycles
                WHERE run_id = ? AND hearing_id = ?
                ORDER BY cycle_index
                """,
                (run_id, hearing_id),
            ).fetchall()
            cycles = tuple(
                self._load_hearing_cycle(connection, run_id, _row_str(row, "cycle_id"))
                for row in rows
            )
            if tuple(item.cycle_index for item in cycles) != tuple(range(1, len(cycles) + 1)):
                raise RepositoryIntegrityError("hearing cycle history is not contiguous")
            return cycles
        finally:
            connection.close()

    def list_hearing_rounds(
        self,
        run_id: str,
        hearing_id: str,
    ) -> tuple[HearingRound, ...]:
        require_reference_token(run_id, "hearing repository run_id")
        require_reference_token(hearing_id, "hearing session ID")
        connection = self._host._connection(require_hardening=True, require_m4=True)
        try:
            self._load_hearing_session(connection, run_id, hearing_id)
            return self._list_hearing_rounds(connection, run_id, hearing_id)
        finally:
            connection.close()

    def load_hearing_record(
        self,
        run_id: str,
        hearing_id: str,
    ) -> HearingRecord | None:
        require_reference_token(run_id, "hearing repository run_id")
        require_reference_token(hearing_id, "hearing session ID")
        connection = self._host._connection(require_hardening=True, require_m4=True)
        try:
            session = self._load_hearing_session(connection, run_id, hearing_id)
            if not self._list_hearing_rounds(connection, run_id, hearing_id):
                return None
            return self._rebuild_hearing_record(
                connection,
                run_id=run_id,
                case_id=session.case_id,
                hearing_id=hearing_id,
            )
        finally:
            connection.close()

    def load_hearing_budget_usage(
        self,
        run_id: str,
        hearing_id: str,
    ) -> HearingBudgetUsage:
        """Rebuild conservative hearing budgets from all durable request/outcome roots."""

        require_reference_token(run_id, "hearing repository run_id")
        require_reference_token(hearing_id, "hearing session ID")
        connection = self._host._connection(require_hardening=True, require_m4=True)
        try:
            session = self._load_hearing_session(connection, run_id, hearing_id)
            return self._load_hearing_budget_usage(
                connection,
                run_id=run_id,
                hearing_id=hearing_id,
                session=session,
            )
        finally:
            connection.close()

    def _load_hearing_budget_usage(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        hearing_id: str,
        session: HearingSession,
    ) -> HearingBudgetUsage:
        claim_rows = connection.execute(
            """
                SELECT * FROM m4_model_call_claims
                WHERE run_id = ? AND hearing_id = ?
                ORDER BY request_id
                """,
            (run_id, hearing_id),
        ).fetchall()
        reserved_images = 0
        reserved_pixels = 0
        request_ids: set[str] = set()
        for row in claim_rows:
            request = self._hearing_model_request_from_claim_row(row)
            if (
                request.hearing_session_id != hearing_id
                or request.manifest_id != session.manifest_id
                or request.request_id in request_ids
            ):
                raise RepositoryIntegrityError("hearing budget request scope is invalid")
            expected_images = len(request.media)
            expected_pixels = sum(item.width * item.height for item in request.media)
            if (
                _row_int(row, "reserved_images") != expected_images
                or _row_int(row, "reserved_pixels") != expected_pixels
            ):
                raise RepositoryIntegrityError(
                    "hearing request reservation differs from canonical media"
                )
            request_ids.add(request.request_id)
            reserved_images += expected_images
            reserved_pixels += expected_pixels

        output_tokens = 0
        usage_rows = connection.execute(
            """
            SELECT * FROM m4_hearing_usage_receipts
            WHERE run_id = ? AND hearing_id = ?
            ORDER BY usage_receipt_id
            """,
            (run_id, hearing_id),
        ).fetchall()
        for row in usage_rows:
            usage = self._hearing_usage_receipt_from_row(row)
            if usage.request_ref.artifact_id not in request_ids:
                raise RepositoryIntegrityError("hearing usage refers to an unknown durable request")
            output_tokens += usage.output_tokens

        failure_rows = connection.execute(
            """
            SELECT authority_json, document_sha256
            FROM m4_model_call_failure_authorities
            WHERE run_id = ? AND hearing_id = ?
            ORDER BY request_id, claim_takeover_count
            """,
            (run_id, hearing_id),
        ).fetchall()
        for row in failure_rows:
            raw = _row_str(row, "authority_json")
            try:
                authority = HearingModelCallFailureAuthority.model_validate_json(raw)
            except ValidationError as exc:
                raise RepositoryIntegrityError(
                    "stored hearing failure authority is invalid"
                ) from exc
            _verify_document(raw, _row_str(row, "document_sha256"), authority)
            if authority.request.request_id not in request_ids:
                raise RepositoryIntegrityError(
                    "hearing failure refers to an unknown durable request"
                )
            output_tokens += authority.output_tokens
        if (
            reserved_images > session.max_total_images
            or output_tokens > session.max_total_output_tokens
        ):
            raise RepositoryIntegrityError("persisted hearing exceeds its session budget")
        return HearingBudgetUsage(
            hearing_session_id=hearing_id,
            request_count=len(request_ids),
            reserved_images=reserved_images,
            reserved_pixels=reserved_pixels,
            output_tokens=output_tokens,
            manifest_id=session.manifest_id,
        )

    def _load_hearing_budget_before_primary(
        self,
        connection: sqlite3.Connection,
        *,
        item: BacklogItem,
        checkpoint: HearingCheckpoint,
        aggregate: HearingBudgetUsage,
    ) -> tuple[int, int]:
        """Invert only the current backlog generation from a validated aggregate."""

        rows = connection.execute(
            """
            SELECT * FROM m4_model_call_claims
            WHERE run_id = ? AND hearing_id = ?
            ORDER BY attempt_index, request_id
            """,
            (item.run_id, checkpoint.hearing_session_id),
        ).fetchall()
        current: list[HearingModelRequest] = []
        for row in rows:
            request = self._hearing_model_request_from_claim_row(row)
            if (
                request.cycle_scope_id != checkpoint.cycle_scope_id
                or request.cycle_scope_sha256 != checkpoint.cycle_scope_sha256
                or request.role != item.role
            ):
                continue
            context = request.backlog_retry_context
            if item.retry_generation == 0:
                if context is not None:
                    continue
            elif (
                context is None
                or context.backlog_item_id != item.item_id
                or context.retry_generation != item.retry_generation
            ):
                continue
            current.append(request)

        attempts = tuple(request.attempt_index for request in current)
        if attempts not in {(), (0,), (0, 1)}:
            raise RepositoryIntegrityError(
                "current hearing backlog generation has invalid request history"
            )
        if len(current) == 2:
            primary, repair = current
            if (
                repair.original_request_id != primary.request_id
                or repair.original_response_id is None
                or repair.original_response_content_sha256 is None
                or repair.backlog_retry_context != primary.backlog_retry_context
            ):
                raise RepositoryIntegrityError(
                    "current hearing backlog repair crosses its primary generation"
                )
        if not current:
            return aggregate.reserved_images, aggregate.output_tokens

        current_ids = tuple(request.request_id for request in current)
        placeholders = ", ".join("?" for _ in current_ids)
        usage_rows = connection.execute(
            f"""
            SELECT * FROM m4_hearing_usage_receipts
            WHERE run_id = ? AND request_id IN ({placeholders})
            ORDER BY request_id, usage_receipt_id
            """,
            (item.run_id, *current_ids),
        ).fetchall()
        current_output_tokens = 0
        usage_request_ids: set[str] = set()
        for row in usage_rows:
            usage = self._hearing_usage_receipt_from_row(row)
            request_id = usage.request_ref.artifact_id
            if request_id not in current_ids or request_id in usage_request_ids:
                raise RepositoryIntegrityError(
                    "current hearing generation has invalid usage accounting"
                )
            usage_request_ids.add(request_id)
            current_output_tokens += usage.output_tokens

        failure_rows = connection.execute(
            f"""
            SELECT * FROM m4_model_call_failure_authorities
            WHERE run_id = ? AND request_id IN ({placeholders})
            ORDER BY request_id, claim_takeover_count, authority_id
            """,
            (item.run_id, *current_ids),
        ).fetchall()
        for row in failure_rows:
            failure = self._hearing_model_failure_authority_from_row(
                connection,
                row,
            )
            if failure.request.request_id not in current_ids:
                raise RepositoryIntegrityError(
                    "current hearing generation has invalid failure accounting"
                )
            current_output_tokens += failure.output_tokens

        current_images = len(current[0].media)
        before_images = aggregate.reserved_images - current_images
        before_tokens = aggregate.output_tokens - current_output_tokens
        if before_images < 0 or before_tokens < 0:
            raise RepositoryIntegrityError(
                "current hearing generation exceeds its durable aggregate"
            )
        return before_images, before_tokens

    @staticmethod
    def _hearing_request_history_key(
        request: HearingModelRequest,
    ) -> tuple[int, int, int, int, str]:
        role_order = {
            VlmRole.PROSECUTOR: 0,
            VlmRole.DEFENDER: 1,
            VlmRole.JUDGE: 2,
        }
        context = request.backlog_retry_context
        retry_generation = context.retry_generation if context is not None else 0
        return (
            request.round_index,
            role_order[request.role],
            retry_generation,
            request.attempt_index,
            request.request_id,
        )

    def _ordered_hearing_requests(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        hearing_id: str,
    ) -> tuple[HearingModelRequest, ...]:
        rows = connection.execute(
            """
            SELECT request_id
            FROM m4_model_call_claims
            WHERE run_id = ? AND hearing_id = ?
            ORDER BY request_id
            """,
            (run_id, hearing_id),
        ).fetchall()
        requests = tuple(
            sorted(
                (
                    self._load_hearing_model_request(
                        connection,
                        run_id,
                        _row_str(row, "request_id"),
                    )
                    for row in rows
                ),
                key=self._hearing_request_history_key,
            )
        )
        keys = tuple(self._hearing_request_history_key(item) for item in requests)
        if (
            len({item.request_id for item in requests}) != len(requests)
            or len(keys) != len(set(keys))
            or any(item.hearing_session_id != hearing_id for item in requests)
        ):
            raise RepositoryIntegrityError(
                "hearing request history is duplicated or crosses session authority"
            )
        return requests

    @staticmethod
    def _request_map(
        requests: tuple[HearingModelRequest, ...],
    ) -> dict[str, HearingModelRequest]:
        return {item.request_id: item for item in requests}

    def list_hearing_model_requests(
        self,
        run_id: str,
        hearing_id: str,
    ) -> tuple[HearingModelRequest, ...]:
        require_reference_token(run_id, "hearing repository run_id")
        require_reference_token(hearing_id, "hearing session ID")
        connection = self._host._connection(require_hardening=True, require_m4=True)
        try:
            connection.execute("BEGIN")
            self._load_hearing_session(connection, run_id, hearing_id)
            return self._ordered_hearing_requests(connection, run_id, hearing_id)
        finally:
            connection.close()

    def list_hearing_model_responses(
        self,
        run_id: str,
        hearing_id: str,
    ) -> tuple[HearingModelResponse, ...]:
        require_reference_token(run_id, "hearing repository run_id")
        require_reference_token(hearing_id, "hearing session ID")
        connection = self._host._connection(require_hardening=True, require_m4=True)
        try:
            connection.execute("BEGIN")
            self._load_hearing_session(connection, run_id, hearing_id)
            requests = self._ordered_hearing_requests(connection, run_id, hearing_id)
            request_by_id = self._request_map(requests)
            rows = connection.execute(
                """
                SELECT response_id
                FROM m4_model_responses
                WHERE run_id = ? AND hearing_id = ?
                ORDER BY response_id
                """,
                (run_id, hearing_id),
            ).fetchall()
            responses = tuple(
                self._load_hearing_model_response(
                    connection,
                    run_id,
                    _row_str(row, "response_id"),
                )
                for row in rows
            )
            if len({item.response_id for item in responses}) != len(responses):
                raise RepositoryIntegrityError("hearing response history is duplicated")
            try:
                ordered = tuple(
                    sorted(
                        responses,
                        key=lambda item: self._hearing_request_history_key(
                            request_by_id[item.request_id]
                        ),
                    )
                )
            except KeyError as exc:
                raise RepositoryIntegrityError(
                    "hearing response lacks its durable request"
                ) from exc
            return ordered
        finally:
            connection.close()

    def list_hearing_usage_receipts(
        self,
        run_id: str,
        hearing_id: str,
    ) -> tuple[HearingUsageReceipt, ...]:
        require_reference_token(run_id, "hearing repository run_id")
        require_reference_token(hearing_id, "hearing session ID")
        connection = self._host._connection(require_hardening=True, require_m4=True)
        try:
            connection.execute("BEGIN")
            self._load_hearing_session(connection, run_id, hearing_id)
            requests = self._ordered_hearing_requests(connection, run_id, hearing_id)
            request_by_id = self._request_map(requests)
            rows = connection.execute(
                """
                SELECT * FROM m4_hearing_usage_receipts
                WHERE run_id = ? AND hearing_id = ?
                ORDER BY usage_receipt_id
                """,
                (run_id, hearing_id),
            ).fetchall()
            usage_receipts = tuple(self._hearing_usage_receipt_from_row(row) for row in rows)
            if len({item.usage_receipt_id for item in usage_receipts}) != len(usage_receipts):
                raise RepositoryIntegrityError("hearing usage history is duplicated")
            try:
                for usage in usage_receipts:
                    request = request_by_id[usage.request_ref.artifact_id]
                    response = self._load_hearing_model_response(
                        connection,
                        run_id,
                        usage.response_ref.artifact_id,
                    )
                    self._validate_hearing_model_completion(request, response, usage)
                return tuple(
                    sorted(
                        usage_receipts,
                        key=lambda item: self._hearing_request_history_key(
                            request_by_id[item.request_ref.artifact_id]
                        ),
                    )
                )
            except (KeyError, ContractViolation) as exc:
                raise RepositoryIntegrityError(
                    "hearing usage history conflicts with its completed calls"
                ) from exc
        finally:
            connection.close()

    def list_hearing_parse_receipts(
        self,
        run_id: str,
        hearing_id: str,
    ) -> tuple[HearingModelParseReceipt, ...]:
        require_reference_token(run_id, "hearing repository run_id")
        require_reference_token(hearing_id, "hearing session ID")
        connection = self._host._connection(require_hardening=True, require_m4=True)
        try:
            connection.execute("BEGIN")
            self._load_hearing_session(connection, run_id, hearing_id)
            requests = self._ordered_hearing_requests(connection, run_id, hearing_id)
            request_by_id = self._request_map(requests)
            rows = connection.execute(
                """
                SELECT * FROM m4_model_parse_receipts
                WHERE run_id = ? AND hearing_id = ?
                ORDER BY parse_receipt_id
                """,
                (run_id, hearing_id),
            ).fetchall()
            receipts = tuple(self._hearing_parse_receipt_from_row(row) for row in rows)
            if len({item.parse_receipt_id for item in receipts}) != len(receipts):
                raise RepositoryIntegrityError("hearing parse history is duplicated")
            try:
                for receipt in receipts:
                    request = request_by_id[receipt.request_id]
                    response = self._load_hearing_model_response(
                        connection,
                        run_id,
                        receipt.response_id,
                    )
                    self._validate_hearing_parse_call_scope(request, response, receipt)
                return tuple(
                    sorted(
                        receipts,
                        key=lambda item: self._hearing_request_history_key(
                            request_by_id[item.request_id]
                        ),
                    )
                )
            except (KeyError, ContractViolation) as exc:
                raise RepositoryIntegrityError(
                    "hearing parse history conflicts with its completed calls"
                ) from exc
        finally:
            connection.close()

    def list_hearing_failure_authorities(
        self,
        run_id: str,
        hearing_id: str,
    ) -> tuple[HearingModelCallFailureAuthority, ...]:
        """Enumerate every durable provider-boundary failure in one read snapshot."""

        require_reference_token(run_id, "hearing repository run_id")
        require_reference_token(hearing_id, "hearing session ID")
        connection = self._host._connection(require_hardening=True, require_m4=True)
        try:
            connection.execute("BEGIN")
            self._load_hearing_session(connection, run_id, hearing_id)
            requests = self._ordered_hearing_requests(connection, run_id, hearing_id)
            request_by_id = self._request_map(requests)
            rows = connection.execute(
                """
                SELECT authority_json, document_sha256
                FROM m4_model_call_failure_authorities
                WHERE run_id = ? AND hearing_id = ?
                ORDER BY authority_id
                """,
                (run_id, hearing_id),
            ).fetchall()
            authorities: list[HearingModelCallFailureAuthority] = []
            for row in rows:
                raw = _row_str(row, "authority_json")
                try:
                    authority = HearingModelCallFailureAuthority.model_validate_json(raw)
                except ValidationError as exc:
                    raise RepositoryIntegrityError(
                        "stored hearing failure authority is invalid"
                    ) from exc
                _verify_document(raw, _row_str(row, "document_sha256"), authority)
                request = request_by_id.get(authority.request.request_id)
                checkpoint = self._load_hearing_checkpoint(
                    connection,
                    run_id,
                    authority.source_checkpoint_id,
                )
                item = self._load_hearing_backlog_version(
                    connection,
                    run_id,
                    authority.backlog_item_id,
                    authority.backlog_version,
                )
                audit = connection.execute(
                    """
                    SELECT entry_hash, object_kind, object_id, manifest_id
                    FROM audit_entries WHERE run_id = ? AND sequence = ?
                    """,
                    (run_id, authority.closure_audit_sequence),
                ).fetchone()
                if (
                    request != authority.request
                    or checkpoint.checkpoint_id != authority.source_checkpoint_id
                    or checkpoint.checkpoint_sha256 != authority.source_checkpoint_sha256
                    or checkpoint.version != authority.source_checkpoint_version
                    or checkpoint.hearing_session_id != hearing_id
                    or item.item_id != authority.backlog_item_id
                    or item.status != authority.backlog_status
                    or item.attempt_count != authority.backlog_attempt_count
                    or item.retry_generation != authority.retry_generation
                    or audit is None
                    or _row_str(audit, "entry_hash") != authority.closure_audit_entry_hash
                    or _row_str(audit, "object_kind") != ArtifactKind.BACKLOG_ITEM.value
                    or _row_str(audit, "object_id") != authority.backlog_item_id
                    or _row_str(audit, "manifest_id") != authority.manifest_id
                ):
                    raise RepositoryIntegrityError(
                        "hearing failure authority crosses its durable closure roots"
                    )
                authorities.append(authority)
            ordered = tuple(
                sorted(
                    authorities,
                    key=lambda item: (
                        *self._hearing_request_history_key(item.request),
                        item.claim_takeover_count,
                        item.authority_id,
                    ),
                )
            )
            keys = tuple(
                (
                    *self._hearing_request_history_key(item.request),
                    item.claim_takeover_count,
                    item.authority_id,
                )
                for item in ordered
            )
            if len({item.authority_id for item in ordered}) != len(ordered) or len(keys) != len(
                set(keys)
            ):
                raise RepositoryIntegrityError("hearing failure-authority history is duplicated")
            return ordered
        finally:
            connection.close()

    def list_hearing_role_outputs(
        self,
        run_id: str,
        hearing_id: str,
    ) -> tuple[HearingRoleOutput, ...]:
        require_reference_token(run_id, "hearing repository run_id")
        require_reference_token(hearing_id, "hearing session ID")
        connection = self._host._connection(require_hardening=True, require_m4=True)
        try:
            connection.execute("BEGIN")
            self._load_hearing_session(connection, run_id, hearing_id)
            requests = self._ordered_hearing_requests(connection, run_id, hearing_id)
            request_by_id = self._request_map(requests)
            rows = connection.execute(
                """
                SELECT parsed_output_id
                FROM m4_parsed_hearing_outputs
                WHERE run_id = ? AND hearing_id = ?
                ORDER BY parsed_output_id
                """,
                (run_id, hearing_id),
            ).fetchall()
            outputs = tuple(
                self._load_hearing_role_output(
                    connection,
                    run_id,
                    _row_str(row, "parsed_output_id"),
                )
                for row in rows
            )
            if len({item.output_id for item in outputs}) != len(outputs):
                raise RepositoryIntegrityError("hearing role-output history is duplicated")
            try:
                for output in outputs:
                    request = request_by_id[output.request_ref.artifact_id]
                    response = self._load_hearing_model_response(
                        connection,
                        run_id,
                        output.response_ref.artifact_id,
                    )
                    parse_row = connection.execute(
                        """
                        SELECT * FROM m4_model_parse_receipts
                        WHERE run_id = ? AND parse_receipt_id = ?
                        """,
                        (run_id, output.parse_receipt_ref.artifact_id),
                    ).fetchone()
                    if parse_row is None:
                        raise RepositoryIntegrityError(
                            "hearing role output lacks its parse receipt"
                        )
                    receipt = self._hearing_parse_receipt_from_row(parse_row)
                    self._validate_hearing_parse_call_scope(request, response, receipt)
                    self._validate_hearing_parse_binding(receipt, output)
                    self._validate_hearing_role_output_scope(
                        connection,
                        request,
                        response,
                        receipt,
                        output,
                    )
                return tuple(
                    sorted(
                        outputs,
                        key=lambda item: self._hearing_request_history_key(
                            request_by_id[item.request_ref.artifact_id]
                        ),
                    )
                )
            except (KeyError, ContractViolation) as exc:
                raise RepositoryIntegrityError(
                    "hearing role-output history conflicts with its completed calls"
                ) from exc
        finally:
            connection.close()

    def load_hearing_cycle(self, run_id: str, cycle_id: str) -> HearingCycleScope:
        require_reference_token(run_id, "hearing repository run_id")
        require_reference_token(cycle_id, "hearing cycle ID")
        connection = self._host._connection(require_hardening=True, require_m4=True)
        try:
            return self._load_hearing_cycle(connection, run_id, cycle_id)
        finally:
            connection.close()

    def load_precedent_retrieval(
        self,
        run_id: str,
        receipt_id: str,
    ) -> HearingPrecedentRetrievalReceipt:
        require_reference_token(run_id, "hearing repository run_id")
        require_reference_token(receipt_id, "precedent retrieval receipt ID")
        connection = self._host._connection(require_hardening=True, require_m4=True)
        try:
            return self._load_precedent_retrieval(connection, run_id, receipt_id)
        finally:
            connection.close()

    def load_hearing_checkpoint(
        self,
        run_id: str,
        checkpoint_id: str,
    ) -> HearingCheckpoint:
        require_reference_token(run_id, "hearing repository run_id")
        require_reference_token(checkpoint_id, "hearing checkpoint ID")
        connection = self._host._connection(require_hardening=True, require_m4=True)
        try:
            return self._load_hearing_checkpoint(connection, run_id, checkpoint_id)
        finally:
            connection.close()

    def load_hearing_round(self, run_id: str, round_id: str) -> HearingRound:
        require_reference_token(run_id, "hearing repository run_id")
        require_reference_token(round_id, "hearing round ID")
        connection = self._host._connection(require_hardening=True, require_m4=True)
        try:
            return self._load_hearing_round(connection, run_id, round_id)
        finally:
            connection.close()

    @staticmethod
    def _require_sha256(value: str, name: str) -> None:
        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise ValueError(f"{name} must be a lowercase SHA-256")

    def _clock_datetime(self) -> datetime:
        return _parse_utc_timestamp(_utc_timestamp(self._host._clock), "repository clock")

    @staticmethod
    def _validated_hearing_backlog_outcome(
        outcome: HearingBacklogRetryOutcome,
    ) -> HearingBacklogRetryOutcome:
        if isinstance(outcome, HearingBacklogRetrySuccess):
            return HearingBacklogRetrySuccess.model_validate(outcome.model_dump(mode="json"))
        if isinstance(outcome, HearingBacklogRetryFailure):
            return HearingBacklogRetryFailure.model_validate(outcome.model_dump(mode="json"))
        raise TypeError("outcome must be a HearingBacklogRetryOutcome")

    @staticmethod
    def _same_hearing_backlog_identity(current: BacklogItem, updated: BacklogItem) -> bool:
        return (
            current.run_id,
            current.item_id,
            current.case_id,
            current.stage,
            current.role,
            current.reason_code,
            current.stage_input_ref,
            current.stage_input_sha256,
            current.max_attempts,
            current.manifest_id,
        ) == (
            updated.run_id,
            updated.item_id,
            updated.case_id,
            updated.stage,
            updated.role,
            updated.reason_code,
            updated.stage_input_ref,
            updated.stage_input_sha256,
            updated.max_attempts,
            updated.manifest_id,
        )

    def _advance_hearing_backlog(
        self,
        connection: sqlite3.Connection,
        current: BacklogItem,
        updated: BacklogItem,
    ) -> int:
        if not self._same_hearing_backlog_identity(current, updated):
            raise ContractViolation("hearing backlog transition changed immutable identity")
        row = connection.execute(
            """
            SELECT current_version FROM backlog_heads
            WHERE run_id = ? AND item_id = ?
            """,
            (current.run_id, current.item_id),
        ).fetchone()
        if row is None:
            raise RepositoryIntegrityError("hearing backlog item has no current head")
        version = _row_int(row, "current_version")
        stored_current = self._load_hearing_backlog_version(
            connection,
            current.run_id,
            current.item_id,
            version,
        )
        if stored_current != current:
            raise ConcurrentModification("hearing backlog head changed during transition")
        document = _contract_document(updated)
        connection.execute(
            """
            INSERT INTO backlog_item_versions(
                run_id, item_id, version, status, attempt_count,
                retry_generation, lease_id, lease_owner_sha256,
                lease_expires_at, item_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                updated.run_id,
                updated.item_id,
                version + 1,
                updated.status.value,
                updated.attempt_count,
                updated.retry_generation,
                updated.lease_id,
                updated.lease_owner_sha256,
                (
                    _canonical_utc_timestamp(
                        updated.lease_expires_at,
                        "hearing backlog lease expiry",
                    )
                    if updated.lease_expires_at is not None
                    else None
                ),
                document,
                hashlib.sha256(document.encode("utf-8")).hexdigest(),
            ),
        )
        cursor = connection.execute(
            """
            UPDATE backlog_heads SET current_version = ?
            WHERE run_id = ? AND item_id = ? AND current_version = ?
            """,
            (version + 1, current.run_id, current.item_id, version),
        )
        if cursor.rowcount != 1:
            raise ConcurrentModification("hearing backlog head changed during transition")
        return version + 1

    def _load_current_hearing_backlog(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        item_id: str,
    ) -> tuple[BacklogItem, int]:
        row = connection.execute(
            """
            SELECT current_version FROM backlog_heads
            WHERE run_id = ? AND item_id = ?
            """,
            (run_id, item_id),
        ).fetchone()
        if row is None:
            raise ConcurrentModification("hearing backlog lease is no longer current")
        version = _row_int(row, "current_version")
        item = self._load_hearing_backlog_version(
            connection,
            run_id,
            item_id,
            version,
        )
        if item.stage != BacklogStage.HEARING:
            raise ContractViolation("hearing retry cannot consume another backlog stage")
        return item, version

    @staticmethod
    def _require_active_hearing_lease(
        item: BacklogItem,
        lease: BacklogLeaseIdentity,
        *,
        now: datetime,
        allow_expired: bool,
    ) -> None:
        if (
            item.run_id != lease.run_id
            or item.item_id != lease.item_id
            or item.status != BacklogStatus.LEASED
            or item.lease_id != lease.lease_id
            or item.attempt_count != lease.attempt_count
            or item.retry_generation != lease.retry_generation
            or item.lease_owner_sha256 is None
            or item.lease_expires_at is None
        ):
            raise ConcurrentModification("hearing backlog lease identity is stale")
        if not allow_expired and item.lease_expires_at <= now:
            raise ConcurrentModification("hearing backlog lease has expired")

    def _load_hearing_backlog_retry_authority(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        lease: BacklogLeaseIdentity,
        allow_expired: bool,
    ) -> HearingBacklogRetryAuthority:
        item, _ = self._load_current_hearing_backlog(connection, run_id, lease.item_id)
        self._require_active_hearing_lease(
            item,
            lease,
            now=self._clock_datetime(),
            allow_expired=allow_expired,
        )
        loaded = self._host._load_case(connection, run_id, item.case_id)
        case = loaded.snapshot
        if (
            case.case.status != CaseStatus.BACKLOGGED
            or case.case.current_backlog_item_id != item.item_id
            or case.case.manifest_id != item.manifest_id
        ):
            raise ConcurrentModification(
                "hearing backlog lease is not the current Case retry boundary"
            )
        audit_head = self._host._validated_head(connection, run_id)
        stage_request = self._load_hearing_model_request(
            connection,
            run_id,
            item.stage_input_ref.artifact_id,
        )
        if (
            item.stage_input_ref.kind != ArtifactKind.MODEL_REQUEST
            or item.stage_input_sha256 != sha256_hex(stage_request.model_dump(mode="json"))
        ):
            raise RepositoryIntegrityError(
                "hearing backlog stage request differs from immutable item authority"
            )
        session = self._load_hearing_session(
            connection,
            run_id,
            stage_request.hearing_session_id,
        )
        cycle = self._load_hearing_cycle(
            connection,
            run_id,
            stage_request.cycle_scope_id,
        )
        checkpoint = self._load_latest_hearing_checkpoint(
            connection,
            run_id,
            stage_request.hearing_session_id,
        )
        if stage_request.attempt_index == 0:
            primary_template = stage_request
        else:
            if stage_request.original_request_id is None:
                raise RepositoryIntegrityError("repair stage request lacks its primary identity")
            primary_template = self._load_hearing_model_request(
                connection,
                run_id,
                stage_request.original_request_id,
            )

        history = self._load_hearing_backlog_completion_history(
            connection,
            run_id=run_id,
            item=item,
        )
        latest = history[-1] if history else None
        latest_failure_authority = (
            self._load_retry_model_call_failure_authority(
                connection,
                run_id,
                latest.receipt_id,
            )
            if latest is not None
            else None
        )
        if (
            latest is not None
            and isinstance(latest.outcome, HearingBacklogRetryFailure)
            and latest.outcome.reason_code == BacklogReasonCode.PROVIDER_UNAVAILABLE
            and latest_failure_authority is None
        ):
            raise RepositoryIntegrityError(
                "provider failure completion lost or fabricated its retry authority"
            )
        self._verify_initial_hearing_backlog_failure(
            connection,
            item=item,
            stage_request=stage_request,
        )
        if latest is None:
            unfinished = (
                None
                if item.reason_code == BacklogReasonCode.MODEL_OUTPUT_INVALID
                else stage_request
            )
        else:
            latest_outcome = latest.outcome
            if not isinstance(latest_outcome, HearingBacklogRetryFailure):
                raise RepositoryIntegrityError(
                    "active hearing backlog follows a successful completion"
                )
            if latest_outcome.reason_code == BacklogReasonCode.WORKER_LEASE_EXPIRED:
                resume_ref = latest_outcome.lease_expiry_resume_request_ref
                unfinished = (
                    self._load_hearing_model_request(
                        connection,
                        run_id,
                        resume_ref.artifact_id,
                    )
                    if resume_ref is not None
                    else None
                )
            elif latest_outcome.strict_parse_failure is not None:
                unfinished = None
            else:
                unfinished = latest_outcome.request
                persisted = self._load_hearing_model_request(
                    connection,
                    run_id,
                    unfinished.request_id,
                )
                if persisted != unfinished:
                    raise RepositoryIntegrityError(
                        "latest retry failure differs from its unfinished request"
                    )
        prior_primary = (
            self._load_hearing_call_closure(
                connection,
                run_id=run_id,
                request_id=unfinished.original_request_id,
            )
            if unfinished is not None
            and unfinished.attempt_index == 1
            and unfinished.original_request_id is not None
            else None
        )
        usage = self._load_hearing_budget_usage(
            connection,
            run_id=run_id,
            hearing_id=session.session_id,
            session=session,
        )
        (
            reserved_images_before_primary,
            accounted_output_tokens_before_primary,
        ) = self._load_hearing_budget_before_primary(
            connection,
            item=item,
            checkpoint=checkpoint,
            aggregate=usage,
        )
        self._verify_hearing_failure_authority_history(
            connection,
            run_id=run_id,
            hearing_id=session.session_id,
        )
        return HearingBacklogRetryAuthority(
            item=item,
            case=case,
            audit_head=audit_head,
            session=session,
            cycle_scope=cycle,
            checkpoint=checkpoint,
            stage_request=stage_request,
            primary_template_request=primary_template,
            unfinished_request=unfinished,
            reserved_images=usage.reserved_images,
            accounted_output_tokens=usage.output_tokens,
            reserved_images_before_primary=reserved_images_before_primary,
            accounted_output_tokens_before_primary=(accounted_output_tokens_before_primary),
            prior_primary_failure=prior_primary,
            latest_completion=latest,
            latest_failure_authority=latest_failure_authority,
        )

    def _verify_initial_hearing_backlog_failure(
        self,
        connection: sqlite3.Connection,
        *,
        item: BacklogItem,
        stage_request: HearingModelRequest,
    ) -> None:
        if item.reason_code == BacklogReasonCode.MODEL_OUTPUT_INVALID:
            proof = self._load_initial_strict_parse_failure(
                connection,
                item.run_id,
                item.item_id,
            )
            if proof.attempts[0].request != stage_request:
                raise RepositoryIntegrityError(
                    "initial hearing strict proof differs from backlog stage input"
                )
            return
        authority = self._load_initial_model_call_failure_authority(
            connection,
            item.run_id,
            item.item_id,
        )
        if (
            authority.request != stage_request
            or authority.backlog_reason_code != item.reason_code
            or authority.manifest_id != item.manifest_id
        ):
            raise RepositoryIntegrityError(
                "initial hearing provider failure differs from backlog authority"
            )

    def _load_hearing_backlog_completion_history(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        item: BacklogItem,
    ) -> tuple[HearingBacklogCompletionReceipt, ...]:
        rows = connection.execute(
            """
            SELECT * FROM m4_backlog_completion_receipts
            WHERE run_id = ? AND item_id = ?
            ORDER BY attempt_count
            """,
            (run_id, item.item_id),
        ).fetchall()
        receipts = tuple(
            self._hearing_backlog_completion_receipt_from_row(connection, row) for row in rows
        )
        if len(receipts) != item.attempt_count - 1:
            raise RepositoryIntegrityError(
                "leased hearing backlog does not have contiguous completion history"
            )
        generation = 1 if item.reason_code == BacklogReasonCode.MODEL_OUTPUT_INVALID else 0
        for attempt_count, receipt in enumerate(receipts, start=1):
            outcome = receipt.outcome
            if (
                not isinstance(outcome, HearingBacklogRetryFailure)
                or outcome.lease.attempt_count != attempt_count
                or outcome.lease.retry_generation != generation
                or outcome.lease.item_id != item.item_id
                or receipt.backlog_status != BacklogStatus.PENDING
            ):
                raise RepositoryIntegrityError(
                    "hearing backlog completion history cannot authorize another lease"
                )
            generation = outcome.next_retry_generation
        if generation != item.retry_generation:
            raise RepositoryIntegrityError(
                "hearing backlog generation differs from its completion history"
            )
        return receipts

    def _hearing_backlog_outcome_from_row(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> HearingBacklogRetryOutcome:
        raw = _row_str(row, "outcome_json")
        try:
            outcome: HearingBacklogRetryOutcome
            if _row_str(row, "outcome_kind") == "SUCCESS":
                outcome = HearingBacklogRetrySuccess.model_validate_json(raw)
            else:
                outcome = HearingBacklogRetryFailure.model_validate_json(raw)
        except ValidationError as exc:
            raise RepositoryIntegrityError("stored hearing backlog outcome is invalid") from exc
        _verify_document(raw, _row_str(row, "document_sha256"), outcome)
        request = outcome.request
        common = (
            _row_str(row, "run_id"),
            _row_str(row, "outcome_id"),
            _row_str(row, "outcome_kind"),
            _row_str(row, "hearing_id"),
            _row_str(row, "cycle_scope_id"),
            _row_str(row, "cycle_scope_sha256"),
            _row_str(row, "case_id"),
            _row_str(row, "role"),
            _row_str(row, "backlog_item_id"),
            _row_str(row, "lease_identity_sha256"),
            _row_str(row, "lease_id"),
            _row_int(row, "lease_attempt_count"),
            _row_int(row, "retry_generation"),
            _row_str(row, "source_checkpoint_id"),
            _row_str(row, "source_checkpoint_sha256"),
            _row_int(row, "source_checkpoint_version"),
            _row_str(row, "request_id"),
            _row_str(row, "request_sha256"),
            _row_int(row, "next_retry_generation"),
            _row_str(row, "manifest_id"),
        )
        expected_common = (
            outcome.lease.run_id,
            outcome.outcome_id,
            outcome.outcome_kind,
            request.hearing_session_id,
            request.cycle_scope_id,
            request.cycle_scope_sha256,
            request.case_id,
            request.role.value,
            outcome.lease.item_id,
            outcome.lease.lease_identity_sha256,
            outcome.lease.lease_id,
            outcome.lease.attempt_count,
            outcome.lease.retry_generation,
            outcome.source_checkpoint_id,
            outcome.source_checkpoint_sha256,
            outcome.source_checkpoint_version,
            request.request_id,
            request.request_sha256,
            (
                outcome.next_retry_generation
                if isinstance(outcome, HearingBacklogRetryFailure)
                else outcome.lease.retry_generation
            ),
            outcome.manifest_id,
        )
        persisted_request = self._load_hearing_model_request(
            connection,
            outcome.lease.run_id,
            request.request_id,
        )
        if common != expected_common or persisted_request != request:
            raise RepositoryIntegrityError(
                "hearing backlog outcome indexes conflict with canonical content"
            )
        response_refs = canonical_json(
            [ref.model_dump(mode="json") for ref in getattr(outcome, "response_refs", ())]
        )
        if response_refs != _row_str(row, "response_refs_json"):
            raise RepositoryIntegrityError("hearing backlog response refs are not canonical")
        if isinstance(outcome, HearingBacklogRetrySuccess):
            indexed_success = (
                _row_str(row, "response_id"),
                _row_str(row, "parse_receipt_id"),
                _row_str(row, "parsed_output_id"),
                _row_str(row, "next_checkpoint_id"),
                _row_str(row, "next_checkpoint_sha256"),
                _row_int(row, "next_checkpoint_version"),
                _row_optional_str(row, "reason_code"),
                _row_optional_str(row, "next_status"),
                _row_optional_str(row, "strict_parse_failure_proof_id"),
                _row_optional_str(row, "human_review_receipt_id"),
            )
            expected_success = (
                outcome.response.response_id,
                outcome.parse_receipt.parse_receipt_id,
                outcome.parsed_role_output.output_id,
                outcome.next_checkpoint.checkpoint_id,
                outcome.next_checkpoint.checkpoint_sha256,
                outcome.next_checkpoint.version,
                None,
                None,
                None,
                (
                    outcome.human_review_receipt.receipt_id
                    if outcome.human_review_receipt is not None
                    else None
                ),
            )
            if indexed_success != expected_success:
                raise RepositoryIntegrityError("hearing backlog success indexes are invalid")
            parse_row = connection.execute(
                """
                SELECT * FROM m4_model_parse_receipts
                WHERE run_id = ? AND parse_receipt_id = ?
                """,
                (outcome.lease.run_id, outcome.parse_receipt.parse_receipt_id),
            ).fetchone()
            if (
                self._load_hearing_model_response(
                    connection,
                    outcome.lease.run_id,
                    outcome.response.response_id,
                )
                != outcome.response
                or parse_row is None
                or self._hearing_parse_receipt_from_row(parse_row) != outcome.parse_receipt
                or self._load_hearing_role_output(
                    connection,
                    outcome.lease.run_id,
                    outcome.parsed_role_output.output_id,
                )
                != outcome.parsed_role_output
                or self._load_hearing_checkpoint(
                    connection,
                    outcome.lease.run_id,
                    outcome.next_checkpoint.checkpoint_id,
                )
                != outcome.next_checkpoint
            ):
                raise RepositoryIntegrityError(
                    "hearing backlog success crosses its durable call/checkpoint closure"
                )
            if outcome.human_review_receipt is not None and (
                self._load_hearing_human_review_receipt(
                    connection,
                    outcome.lease.run_id,
                    outcome.human_review_receipt.receipt_id,
                )
                != outcome.human_review_receipt
            ):
                raise RepositoryIntegrityError(
                    "hearing backlog success crosses its human-review authority"
                )
        else:
            indexed_failure = (
                _row_optional_str(row, "response_id"),
                _row_optional_str(row, "parse_receipt_id"),
                _row_optional_str(row, "parsed_output_id"),
                _row_optional_str(row, "next_checkpoint_id"),
                _row_optional_str(row, "reason_code"),
                _row_optional_str(row, "next_status"),
                _row_optional_str(row, "strict_parse_failure_proof_id"),
                _row_optional_str(row, "human_review_receipt_id"),
            )
            expected_failure = (
                None,
                None,
                None,
                None,
                outcome.reason_code.value,
                outcome.next_status.value,
                (
                    outcome.strict_parse_failure.proof_id
                    if outcome.strict_parse_failure is not None
                    else None
                ),
                (
                    outcome.human_review_receipt.receipt_id
                    if outcome.human_review_receipt is not None
                    else None
                ),
            )
            if indexed_failure != expected_failure:
                raise RepositoryIntegrityError("hearing backlog failure indexes are invalid")
            if outcome.strict_parse_failure is not None and (
                self._load_retry_strict_parse_failure(
                    connection,
                    outcome.lease.run_id,
                    outcome.strict_parse_failure.proof_id,
                )
                != outcome.strict_parse_failure
            ):
                raise RepositoryIntegrityError("hearing backlog failure crosses its strict proof")
            if outcome.human_review_receipt is not None and (
                self._load_hearing_human_review_receipt(
                    connection,
                    outcome.lease.run_id,
                    outcome.human_review_receipt.receipt_id,
                )
                != outcome.human_review_receipt
            ):
                raise RepositoryIntegrityError(
                    "hearing backlog failure crosses its human-review authority"
                )
        return outcome

    def _hearing_backlog_completion_receipt_from_row(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> HearingBacklogCompletionReceipt:
        raw = _row_str(row, "receipt_json")
        try:
            receipt = HearingBacklogCompletionReceipt.model_validate_json(raw)
        except ValidationError as exc:
            raise RepositoryIntegrityError(
                "stored hearing backlog completion receipt is invalid"
            ) from exc
        _verify_document(raw, _row_str(row, "document_sha256"), receipt)
        outcome_row = connection.execute(
            """
            SELECT * FROM m4_hearing_backlog_retry_outcomes
            WHERE run_id = ? AND outcome_id = ?
            """,
            (receipt.outcome.lease.run_id, receipt.outcome.outcome_id),
        ).fetchone()
        if outcome_row is None:
            raise RepositoryIntegrityError("hearing backlog receipt lacks its outcome")
        outcome = self._hearing_backlog_outcome_from_row(connection, outcome_row)
        item_identity = connection.execute(
            """
            SELECT case_id, role FROM backlog_items
            WHERE run_id = ? AND item_id = ?
            """,
            (receipt.outcome.lease.run_id, receipt.outcome.lease.item_id),
        ).fetchone()
        if item_identity is None:
            raise RepositoryIntegrityError("hearing backlog receipt lacks its item identity")
        indexed = (
            _row_str(row, "run_id"),
            _row_str(row, "receipt_id"),
            _row_str(row, "receipt_sha256"),
            _row_str(row, "item_id"),
            _row_str(row, "case_id"),
            _row_str(row, "hearing_id"),
            _row_str(row, "role"),
            _row_str(row, "outcome_kind"),
            _row_str(row, "outcome_id"),
            _row_str(row, "lease_identity_sha256"),
            _row_str(row, "lease_id"),
            _row_int(row, "attempt_count"),
            _row_int(row, "retry_generation"),
            _row_str(row, "backlog_status"),
            _row_str(row, "source_checkpoint_id"),
            _row_str(row, "source_checkpoint_sha256"),
            _row_int(row, "source_checkpoint_version"),
            _row_str(row, "resulting_checkpoint_id"),
            _row_str(row, "resulting_checkpoint_sha256"),
            _row_int(row, "resulting_checkpoint_version"),
            _row_str(row, "completion_case_status"),
            _row_int(row, "completion_case_revision"),
            _row_int(row, "completion_audit_sequence"),
            _row_str(row, "completion_audit_entry_hash"),
            _row_str(row, "manifest_id"),
        )
        expected = (
            receipt.outcome.lease.run_id,
            receipt.receipt_id,
            receipt.receipt_sha256,
            receipt.outcome.lease.item_id,
            _row_str(item_identity, "case_id"),
            receipt.outcome.request.hearing_session_id,
            receipt.outcome.role.value
            if isinstance(receipt.outcome, HearingBacklogRetryFailure)
            else receipt.outcome.request.role.value,
            receipt.outcome.outcome_kind,
            receipt.outcome.outcome_id,
            receipt.outcome.lease.lease_identity_sha256,
            receipt.outcome.lease.lease_id,
            receipt.outcome.lease.attempt_count,
            receipt.outcome.lease.retry_generation,
            receipt.backlog_status.value,
            receipt.source_checkpoint_id,
            receipt.source_checkpoint_sha256,
            receipt.source_checkpoint_version,
            receipt.resulting_checkpoint_id,
            receipt.resulting_checkpoint_sha256,
            receipt.resulting_checkpoint_version,
            receipt.completion_case_status.value,
            receipt.completion_case_revision,
            receipt.completion_audit_sequence,
            receipt.completion_audit_entry_hash,
            receipt.manifest_id,
        )
        if outcome != receipt.outcome or indexed != expected:
            raise RepositoryIntegrityError(
                "hearing backlog receipt indexes conflict with canonical content"
            )
        backlog_version = _row_int(row, "backlog_version")
        closed = self._load_hearing_backlog_version(
            connection,
            receipt.outcome.lease.run_id,
            receipt.outcome.lease.item_id,
            backlog_version,
        )
        if (
            closed.status != receipt.backlog_status
            or closed.attempt_count != receipt.outcome.lease.attempt_count
        ):
            raise RepositoryIntegrityError("hearing backlog receipt binds another item version")
        return receipt

    def _load_retry_strict_parse_failure(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        proof_id: str,
    ) -> HearingStrictParseFailureProof:
        row = connection.execute(
            """
            SELECT * FROM m4_hearing_strict_parse_failure_proofs
            WHERE run_id = ? AND proof_id = ? AND closure_kind = 'RETRY_FAILURE'
            """,
            (run_id, proof_id),
        ).fetchone()
        if row is None:
            raise RepositoryIntegrityError("hearing retry strict proof is absent")
        raw = _row_str(row, "proof_json")
        try:
            proof = HearingStrictParseFailureProof.model_validate_json(raw)
        except ValidationError as exc:
            raise RepositoryIntegrityError("stored hearing retry strict proof is invalid") from exc
        _verify_document(raw, _row_str(row, "document_sha256"), proof)
        indexed = (
            _row_str(row, "run_id"),
            _row_str(row, "proof_id"),
            _row_str(row, "source_checkpoint_id"),
            _row_str(row, "source_checkpoint_sha256"),
            _row_int(row, "source_checkpoint_version"),
            _row_str(row, "backlog_item_id"),
            _row_str(row, "lease_identity_sha256"),
            _row_str(row, "lease_id"),
            _row_int(row, "lease_attempt_count"),
            _row_int(row, "retry_generation"),
            _row_str(row, "role"),
            _row_str(row, "primary_attempt_id"),
            _row_str(row, "repair_attempt_id"),
        )
        expected = (
            proof.lease.run_id,
            proof.proof_id,
            proof.source_checkpoint_id,
            proof.source_checkpoint_sha256,
            proof.source_checkpoint_version,
            proof.lease.item_id,
            proof.lease.lease_identity_sha256,
            proof.lease.lease_id,
            proof.lease.attempt_count,
            proof.lease.retry_generation,
            proof.role.value,
            proof.attempts[0].attempt_id,
            proof.attempts[1].attempt_id,
        )
        if indexed != expected:
            raise RepositoryIntegrityError(
                "hearing retry strict proof indexes conflict with content"
            )
        for attempt in proof.attempts:
            attempt_row = connection.execute(
                """
                SELECT attempt_json, document_sha256
                FROM m4_hearing_strict_parse_failure_attempts
                WHERE run_id = ? AND attempt_id = ?
                """,
                (run_id, attempt.attempt_id),
            ).fetchone()
            if attempt_row is None:
                raise RepositoryIntegrityError("hearing retry strict attempt is absent")
            attempt_raw = _row_str(attempt_row, "attempt_json")
            try:
                stored_attempt = HearingStrictParseFailureAttempt.model_validate_json(attempt_raw)
            except ValidationError as exc:
                raise RepositoryIntegrityError(
                    "stored hearing retry strict attempt is invalid"
                ) from exc
            _verify_document(
                attempt_raw,
                _row_str(attempt_row, "document_sha256"),
                stored_attempt,
            )
            if stored_attempt != attempt:
                raise RepositoryIntegrityError(
                    "hearing retry strict proof differs from its attempt"
                )
        return proof

    def _load_hearing_call_closure(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        request_id: str,
    ) -> HearingCallClosure:
        request = self._load_hearing_model_request(connection, run_id, request_id)
        response_rows = connection.execute(
            "SELECT response_id FROM m4_model_responses WHERE run_id = ? AND request_id = ?",
            (run_id, request_id),
        ).fetchall()
        parse_rows = connection.execute(
            "SELECT * FROM m4_model_parse_receipts WHERE run_id = ? AND request_id = ?",
            (run_id, request_id),
        ).fetchall()
        usage_rows = connection.execute(
            "SELECT * FROM m4_hearing_usage_receipts WHERE run_id = ? AND request_id = ?",
            (run_id, request_id),
        ).fetchall()
        if len(response_rows) != 1 or len(parse_rows) != 1 or len(usage_rows) != 1:
            raise RepositoryIntegrityError("hearing call closure is not exactly persisted")
        return HearingCallClosure(
            request=request,
            response=self._load_hearing_model_response(
                connection,
                run_id,
                _row_str(response_rows[0], "response_id"),
            ),
            parse_receipt=self._hearing_parse_receipt_from_row(parse_rows[0]),
            usage=self._hearing_usage_receipt_from_row(usage_rows[0]),
        )

    def _verify_hearing_failure_authority_history(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        hearing_id: str,
    ) -> None:
        rows = connection.execute(
            """
            SELECT * FROM m4_model_call_failure_authorities
            WHERE run_id = ? AND hearing_id = ?
            ORDER BY request_id, claim_takeover_count, authority_id
            """,
            (run_id, hearing_id),
        ).fetchall()
        identities: set[str] = set()
        for row in rows:
            raw = _row_str(row, "authority_json")
            try:
                authority = HearingModelCallFailureAuthority.model_validate_json(raw)
            except ValidationError as exc:
                raise RepositoryIntegrityError(
                    "stored hearing failure authority is invalid"
                ) from exc
            _verify_document(raw, _row_str(row, "document_sha256"), authority)
            if (
                authority.authority_id in identities
                or authority.hearing_session_id != hearing_id
                or self._load_hearing_model_request(
                    connection,
                    run_id,
                    authority.request.request_id,
                )
                != authority.request
                or authority.authority_id != _row_str(row, "authority_id")
                or authority.backlog_item_id != _row_str(row, "backlog_item_id")
                or authority.backlog_version != _row_int(row, "backlog_version")
                or authority.closure_case_revision
                != _row_int(
                    row,
                    "closure_case_revision",
                )
                or authority.closure_audit_sequence
                != _row_int(
                    row,
                    "closure_audit_sequence",
                )
            ):
                raise RepositoryIntegrityError(
                    "hearing failure authority history crosses durable roots"
                )
            if authority.closure_kind == ModelCallFailureClosureKind.RETRY_FAILURE:
                receipt_id = authority.completion_receipt_id
                if (
                    receipt_id is None
                    or self._load_retry_model_call_failure_authority(
                        connection,
                        run_id,
                        receipt_id,
                    )
                    != authority
                ):
                    raise RepositoryIntegrityError(
                        "retry provider failure is not bidirectionally bound"
                    )
            identities.add(authority.authority_id)

    def _commit_hearing_backlog_retry(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        expected_case_revision: int,
        expected_audit_head: AuditHead,
        outcome: HearingBacklogRetryOutcome,
        allow_expired: bool,
        model_call_failure: HearingModelCallFailureIntent | None = None,
    ) -> HearingBacklogRetryCommit:
        replay_rows = connection.execute(
            """
            SELECT * FROM m4_backlog_completion_receipts
            WHERE run_id = ? AND (
                outcome_id = ? OR
                (item_id = ? AND lease_identity_sha256 = ?)
            )
            """,
            (
                run_id,
                outcome.outcome_id,
                outcome.lease.item_id,
                outcome.lease.lease_identity_sha256,
            ),
        ).fetchall()
        if replay_rows:
            if len(replay_rows) != 1:
                raise RepositoryIntegrityError(
                    "hearing backlog lease selects multiple completion receipts"
                )
            return self._replay_hearing_backlog_retry(
                connection,
                row=replay_rows[0],
                expected_case_revision=expected_case_revision,
                expected_audit_head=expected_audit_head,
                outcome=outcome,
                model_call_failure=model_call_failure,
            )

        authority = self._load_hearing_backlog_retry_authority(
            connection,
            run_id=run_id,
            lease=outcome.lease,
            allow_expired=allow_expired,
        )
        if authority.case.revision != expected_case_revision:
            raise ConcurrentModification("Case revision changed before hearing retry commit")
        self._require_expected_head(authority.audit_head, expected_audit_head)
        self._validate_retry_outcome_authority(
            connection,
            authority=authority,
            outcome=outcome,
            model_call_failure=model_call_failure,
        )

        if isinstance(outcome, HearingBacklogRetrySuccess):
            if outcome.human_review_receipt is not None:
                self._insert_hearing_human_review_receipt(
                    connection,
                    outcome.human_review_receipt,
                )
            self._insert_hearing_checkpoint(connection, outcome.next_checkpoint)
            self._host._fault("hearing.backlog_retry.after_checkpoint")
        else:
            if outcome.strict_parse_failure is not None:
                self._insert_retry_strict_parse_failure(
                    connection,
                    outcome.strict_parse_failure,
                )
                self._host._fault("hearing.backlog_retry.after_strict_failure")
            if outcome.human_review_receipt is not None:
                self._insert_hearing_human_review_receipt(
                    connection,
                    outcome.human_review_receipt,
                )
                self._host._fault("hearing.backlog_retry.after_human_receipt")

        self._insert_hearing_backlog_retry_outcome(connection, outcome)
        self._host._fault("hearing.backlog_retry.after_outcome")
        status = (
            BacklogStatus.COMPLETED
            if isinstance(outcome, HearingBacklogRetrySuccess)
            else outcome.next_status
        )
        retry_generation = (
            outcome.lease.retry_generation
            if isinstance(outcome, HearingBacklogRetrySuccess)
            else outcome.next_retry_generation
        )
        closed = BacklogItem.model_validate(
            {
                **authority.item.model_dump(mode="json", exclude_computed_fields=True),
                "status": status.value,
                "retry_generation": retry_generation,
                "lease_id": None,
                "lease_owner_sha256": None,
                "lease_expires_at": None,
            }
        )
        backlog_version = self._advance_hearing_backlog(
            connection,
            authority.item,
            closed,
        )
        self._host._fault("hearing.backlog_retry.after_backlog")

        completion_status, timeline_entry = self._hearing_retry_case_transition(
            authority,
            outcome,
            status=status,
            retry_generation=retry_generation,
        )
        current_item_id = closed.item_id if status == BacklogStatus.PENDING else None
        new_case = self._case_with_updates(
            authority.case.case,
            status=completion_status,
            current_backlog_item_id=current_item_id,
            timeline_entry=timeline_entry,
        )
        loaded = self._host._load_case(
            connection,
            run_id,
            authority.item.case_id,
        )
        if loaded.snapshot != authority.case:
            raise ConcurrentModification("Case changed during hearing retry commit")
        committed_case = self._commit_case_version(
            connection,
            previous=authority.case,
            previous_document_sha256=loaded.document_sha256,
            new_case=new_case,
            expected_head=expected_audit_head,
            object_ref=ArtifactRef(
                kind=ArtifactKind.BACKLOG_ITEM,
                artifact_id=authority.item.item_id,
            ),
            fault_prefix="hearing.backlog_retry",
        )
        audit_head = self._audit_head_after_expected(connection, expected_audit_head)
        resulting_checkpoint = (
            outcome.next_checkpoint
            if isinstance(outcome, HearingBacklogRetrySuccess)
            else authority.checkpoint
        )
        receipt = HearingBacklogCompletionReceipt(
            outcome=outcome,
            backlog_status=status,
            source_checkpoint_id=authority.checkpoint.checkpoint_id,
            source_checkpoint_sha256=authority.checkpoint.checkpoint_sha256,
            source_checkpoint_version=authority.checkpoint.version,
            resulting_checkpoint_id=resulting_checkpoint.checkpoint_id,
            resulting_checkpoint_sha256=resulting_checkpoint.checkpoint_sha256,
            resulting_checkpoint_version=resulting_checkpoint.version,
            completion_case_status=completion_status,
            completion_case_revision=committed_case.revision,
            completion_audit_sequence=audit_head.sequence,
            completion_audit_entry_hash=audit_head.entry_hash,
            manifest_id=authority.item.manifest_id,
        )
        self._insert_hearing_backlog_completion_receipt(
            connection,
            receipt=receipt,
            item=closed,
            backlog_version=backlog_version,
        )
        self._host._fault("hearing.backlog_retry.after_receipt")
        failure_authority = None
        if model_call_failure is not None:
            failure_authority = self._build_retry_model_call_failure_authority(
                model_call_failure,
                item=closed,
                checkpoint=authority.checkpoint,
                lease=outcome.lease,
                backlog_version=backlog_version,
                completion_receipt=receipt,
                closure_case_revision=committed_case.revision,
                audit_head=audit_head,
            )
            self._insert_model_call_failure_authority(
                connection,
                failure_authority,
            )
            self._host._fault("hearing.backlog_retry.after_failure_authority")
        return HearingBacklogRetryCommit(
            item=closed,
            receipt=receipt,
            case=committed_case,
            checkpoint=resulting_checkpoint,
            audit_head=audit_head,
            created=True,
            failure_authority=failure_authority,
        )

    def _validate_retry_outcome_authority(
        self,
        connection: sqlite3.Connection,
        *,
        authority: HearingBacklogRetryAuthority,
        outcome: HearingBacklogRetryOutcome,
        model_call_failure: HearingModelCallFailureIntent | None,
    ) -> None:
        role = authority.item.role
        if role is None:
            raise RepositoryIntegrityError("hearing backlog item lacks its role")
        if (
            outcome.lease != authority.lease
            or outcome.source_checkpoint_id != authority.checkpoint.checkpoint_id
            or outcome.source_checkpoint_sha256 != authority.checkpoint.checkpoint_sha256
            or outcome.source_checkpoint_version != authority.checkpoint.version
            or outcome.request.role != role
            or outcome.manifest_id != authority.item.manifest_id
        ):
            raise ConcurrentModification(
                "hearing retry outcome does not consume the loaded checkpoint authority"
            )
        persisted_request = self._load_hearing_model_request(
            connection,
            authority.item.run_id,
            outcome.request.request_id,
        )
        if persisted_request != outcome.request:
            raise HearingPersistenceConflict(
                "hearing retry outcome request differs from durable claim authority"
            )
        if model_call_failure is not None:
            if (
                not isinstance(outcome, HearingBacklogRetryFailure)
                or outcome.reason_code == BacklogReasonCode.WORKER_LEASE_EXPIRED
                or outcome.strict_parse_failure is not None
                or model_call_failure.request != outcome.request
                or model_call_failure.backlog_reason_code != outcome.reason_code
            ):
                raise ContractViolation(
                    "provider failure intent does not bind the exact retry outcome"
                )
            self._require_hearing_model_failure_fence(
                connection,
                model_call_failure,
            )
        elif (
            isinstance(outcome, HearingBacklogRetryFailure)
            and outcome.reason_code == BacklogReasonCode.PROVIDER_UNAVAILABLE
        ):
            raise ContractViolation(
                "provider-unavailable retry requires exact fenced failure authority"
            )
        if isinstance(outcome, HearingBacklogRetrySuccess):
            if outcome.session != authority.session:
                raise ConcurrentModification("hearing retry success changed its session")
            response = self._load_hearing_model_response(
                connection,
                authority.item.run_id,
                outcome.response.response_id,
            )
            parse_row = connection.execute(
                """
                SELECT * FROM m4_model_parse_receipts
                WHERE run_id = ? AND parse_receipt_id = ?
                """,
                (authority.item.run_id, outcome.parse_receipt.parse_receipt_id),
            ).fetchone()
            if parse_row is None:
                raise EvidenceMissing("hearing retry success parse receipt is missing")
            parsed = self._hearing_parse_receipt_from_row(parse_row)
            output = self._load_hearing_role_output(
                connection,
                authority.item.run_id,
                outcome.parsed_role_output.output_id,
            )
            latest = self._load_latest_hearing_checkpoint(
                connection,
                authority.item.run_id,
                authority.session.session_id,
            )
            if (
                response != outcome.response
                or parsed != outcome.parse_receipt
                or output != outcome.parsed_role_output
                or latest != authority.checkpoint
            ):
                raise HearingPersistenceConflict(
                    "hearing retry success differs from its durable call/checkpoint history"
                )
            return

        if outcome.reason_code == BacklogReasonCode.WORKER_LEASE_EXPIRED:
            expected_resume_ref = (
                ArtifactRef(
                    kind=ArtifactKind.MODEL_REQUEST,
                    artifact_id=authority.unfinished_request.request_id,
                )
                if authority.unfinished_request is not None
                else None
            )
            if (
                outcome.request != authority.stage_request
                or outcome.request_binding != "BACKLOG_STAGE_INPUT"
                or outcome.lease_expiry_resume_request_ref != expected_resume_ref
            ):
                raise ContractViolation(
                    "hearing lease-expiry outcome does not preserve its exact retry mode"
                )
            return
        proof = outcome.strict_parse_failure
        if proof is not None:
            primary_request = proof.attempts[0].request
            repair_request = proof.attempts[1].request
            self._require_hearing_retry_request_generation(authority, primary_request)
            self._require_hearing_retry_request_generation(authority, repair_request)
            primary_call = self._validated_hearing_retry_repair_request(
                connection,
                authority=authority,
                repair_request=repair_request,
            )
            unfinished = authority.unfinished_request
            if unfinished is not None:
                expected_unfinished = (
                    primary_request if unfinished.attempt_index == 0 else repair_request
                )
                if expected_unfinished != unfinished:
                    raise ContractViolation(
                        "hearing strict retry changed its exact unfinished call"
                    )
                if (
                    unfinished.attempt_index == 1
                    and primary_call != authority.prior_primary_failure
                ):
                    raise RepositoryIntegrityError(
                        "hearing repair-only strict retry changed its primary closure"
                    )
            for attempt in proof.attempts:
                call = self._load_hearing_call_closure(
                    connection,
                    run_id=authority.item.run_id,
                    request_id=attempt.request.request_id,
                )
                if (
                    call.request != attempt.request
                    or call.response != attempt.response
                    or call.parse_receipt != attempt.parse_receipt
                ):
                    raise HearingPersistenceConflict(
                        "hearing strict retry proof differs from durable call history"
                    )
            return
        self._validate_hearing_retry_failure_request(
            connection,
            authority=authority,
            request=outcome.request,
        )

    @staticmethod
    def _require_hearing_model_failure_fence(
        connection: sqlite3.Connection,
        intent: HearingModelCallFailureIntent,
    ) -> None:
        request = intent.request
        row = connection.execute(
            """
            SELECT * FROM m4_model_call_claims
            WHERE run_id = ? AND request_id = ?
            """,
            (request.run_id, request.request_id),
        ).fetchone()
        owner_sha256 = hashlib.sha256(intent.owner_token.encode("utf-8")).hexdigest()
        expected = (
            request.request_sha256,
            request.cache_key,
            request.hearing_session_id,
            request.cycle_scope_id,
            request.cycle_scope_sha256,
            request.case_id,
            request.role.value,
            len(request.media),
            sum(media.width * media.height for media in request.media),
            owner_sha256,
            _canonical_utc_timestamp(
                intent.claim_lease_expires_at,
                "hearing failure claim expiry",
            ),
            intent.claim_takeover_count,
            "ACTIVE",
            None,
        )
        observed = (
            (
                _row_str(row, "request_sha256"),
                _row_str(row, "cache_key"),
                _row_str(row, "hearing_id"),
                _row_str(row, "cycle_scope_id"),
                _row_str(row, "cycle_scope_sha256"),
                _row_str(row, "case_id"),
                _row_str(row, "role"),
                _row_int(row, "reserved_images"),
                _row_int(row, "reserved_pixels"),
                _row_str(row, "owner_token_sha256"),
                _row_str(row, "lease_expires_at"),
                _row_int(row, "takeover_count"),
                _row_str(row, "status"),
                _row_optional_str(row, "response_id"),
            )
            if row is not None
            else None
        )
        if observed != expected:
            raise ConcurrentModification("hearing provider failure lost its exact claim fence")

    @staticmethod
    def _require_hearing_retry_request_generation(
        authority: HearingBacklogRetryAuthority,
        request: HearingModelRequest,
    ) -> None:
        context = request.backlog_retry_context
        generation = authority.item.retry_generation
        if generation == 0:
            if context is not None:
                raise ContractViolation(
                    "generation-zero hearing retry request gained backlog context"
                )
            return
        if (
            context is None
            or context.backlog_item_id != authority.item.item_id
            or context.retry_generation != generation
        ):
            raise ContractViolation("hearing retry request belongs to another backlog generation")

    def _validated_hearing_retry_repair_request(
        self,
        connection: sqlite3.Connection,
        *,
        authority: HearingBacklogRetryAuthority,
        repair_request: HearingModelRequest,
    ) -> HearingCallClosure:
        if repair_request.attempt_index != 1 or repair_request.original_request_id is None:
            raise ContractViolation("hearing retry repair request lacks its primary identity")
        primary = self._load_hearing_call_closure(
            connection,
            run_id=authority.item.run_id,
            request_id=repair_request.original_request_id,
        )
        if (
            primary.request.attempt_index != 0
            or primary.request.role != repair_request.role
            or primary.parse_receipt.status != ModelParseStatus.REPAIR_REQUIRED
            or primary.parse_receipt.repair_request_id != repair_request.request_id
            or repair_request.original_request_id != primary.request.request_id
            or repair_request.original_response_id != primary.response.response_id
            or repair_request.original_response_content_sha256 != primary.response.content_sha256
            or repair_request.backlog_retry_context != primary.request.backlog_retry_context
        ):
            raise HearingPersistenceConflict(
                "hearing retry repair lacks its exact persisted primary closure"
            )
        return primary

    def _validate_hearing_retry_failure_request(
        self,
        connection: sqlite3.Connection,
        *,
        authority: HearingBacklogRetryAuthority,
        request: HearingModelRequest,
    ) -> None:
        self._require_hearing_retry_request_generation(authority, request)
        unfinished = authority.unfinished_request
        if request.attempt_index == 0:
            if unfinished is not None and request != unfinished:
                raise ContractViolation(
                    "hearing retry failure changed its exact unfinished primary"
                )
            return

        primary = self._validated_hearing_retry_repair_request(
            connection,
            authority=authority,
            repair_request=request,
        )
        if unfinished is None:
            self._require_hearing_retry_request_generation(authority, primary.request)
            return
        if unfinished.attempt_index == 0:
            if primary.request != unfinished:
                raise ContractViolation(
                    "hearing retry repair did not follow its unfinished primary"
                )
            return
        if request != unfinished or primary != authority.prior_primary_failure:
            raise ContractViolation("hearing retry failure changed its exact unfinished repair")

    @staticmethod
    def _hearing_retry_case_transition(
        authority: HearingBacklogRetryAuthority,
        outcome: HearingBacklogRetryOutcome,
        *,
        status: BacklogStatus,
        retry_generation: int,
    ) -> tuple[CaseStatus, TimelineEntry]:
        sequence = len(authority.case.case.timeline)
        if isinstance(outcome, HearingBacklogRetrySuccess):
            human = outcome.human_review_receipt
            if human is not None:
                return (
                    CaseStatus.HUMAN_REVIEW,
                    TimelineEntry(
                        sequence=sequence,
                        action=AuditAction.CASE_STATE_CHANGED.value,
                        stage="HEARING",
                        object_ref=human.receipt_id,
                        details={
                            "reason": human.reason.value,
                            "hearing_session_id": human.hearing_session_id,
                            "judge_cycle": human.judge_cycle,
                        },
                    ),
                )
            return (
                CaseStatus.DELIBERATING,
                TimelineEntry(
                    sequence=sequence,
                    action=AuditAction.CASE_STATE_CHANGED.value,
                    stage="BACKLOG",
                    object_ref=authority.item.item_id,
                    details={
                        "outcome": "SUCCESS",
                        "role": outcome.request.role.value,
                        "status": CaseStatus.DELIBERATING.value,
                        "retry_generation": retry_generation,
                    },
                ),
            )
        return (
            CaseStatus.BACKLOGGED if status == BacklogStatus.PENDING else CaseStatus.HUMAN_REVIEW,
            TimelineEntry(
                sequence=sequence,
                action=AuditAction.CASE_STATE_CHANGED.value,
                stage="BACKLOG",
                object_ref=authority.item.item_id,
                details={
                    "outcome": "FAILURE",
                    "reason_code": outcome.reason_code.value,
                    "status": status.value,
                    "retry_generation": retry_generation,
                },
            ),
        )

    def _replay_hearing_backlog_retry(
        self,
        connection: sqlite3.Connection,
        *,
        row: sqlite3.Row,
        expected_case_revision: int,
        expected_audit_head: AuditHead,
        outcome: HearingBacklogRetryOutcome,
        model_call_failure: HearingModelCallFailureIntent | None,
    ) -> HearingBacklogRetryCommit:
        receipt = self._hearing_backlog_completion_receipt_from_row(connection, row)
        if receipt.outcome != outcome:
            raise HearingPersistenceConflict(
                "hearing backlog lease already closed with another outcome"
            )
        if receipt.completion_case_revision != expected_case_revision + 1:
            raise HearingPersistenceConflict(
                "hearing backlog replay changed its expected Case revision"
            )
        failure_authority = self._load_retry_model_call_failure_authority(
            connection,
            outcome.lease.run_id,
            receipt.receipt_id,
        )
        if (
            isinstance(outcome, HearingBacklogRetryFailure)
            and outcome.reason_code == BacklogReasonCode.PROVIDER_UNAVAILABLE
            and failure_authority is None
        ):
            raise RepositoryIntegrityError(
                "provider failure replay lacks immutable retry authority"
            )
        if model_call_failure is not None and (
            failure_authority is None
            or not self._failure_intent_matches_authority(
                model_call_failure,
                failure_authority,
            )
        ):
            raise HearingPersistenceConflict(
                "provider failure replay changed its exact claim fence"
            )
        self._verify_transition_audit(
            connection,
            run_id=outcome.lease.run_id,
            audit_sequence=receipt.completion_audit_sequence,
            expected_head=expected_audit_head,
            object_id=outcome.lease.item_id,
            object_kind=ArtifactKind.BACKLOG_ITEM,
        )
        committed_case = self._load_case_revision(
            connection,
            outcome.lease.run_id,
            outcome.request.case_id,
            receipt.completion_case_revision,
        )
        backlog_version = _row_int(row, "backlog_version")
        item = self._load_hearing_backlog_version(
            connection,
            outcome.lease.run_id,
            outcome.lease.item_id,
            backlog_version,
        )
        checkpoint = self._load_hearing_checkpoint(
            connection,
            outcome.lease.run_id,
            receipt.resulting_checkpoint_id,
        )
        audit_head = AuditHead(
            run_id=outcome.lease.run_id,
            manifest_id=receipt.manifest_id,
            run_revision=expected_audit_head.run_revision + 1,
            sequence=receipt.completion_audit_sequence,
            entry_hash=receipt.completion_audit_entry_hash,
        )
        return HearingBacklogRetryCommit(
            item=item,
            receipt=receipt,
            case=committed_case,
            checkpoint=checkpoint,
            audit_head=audit_head,
            created=False,
            failure_authority=failure_authority,
        )

    @staticmethod
    def _failure_intent_matches_authority(
        intent: HearingModelCallFailureIntent,
        authority: HearingModelCallFailureAuthority,
    ) -> bool:
        return (
            intent.request == authority.request
            and hashlib.sha256(intent.owner_token.encode("utf-8")).hexdigest()
            == authority.claim_owner_sha256
            and intent.claim_lease_expires_at == authority.claim_lease_expires_at
            and intent.claim_takeover_count == authority.claim_takeover_count
            and intent.failure_code == authority.failure_code
            and intent.delivery_certainty == authority.delivery_certainty
            and intent.backlog_reason_code == authority.backlog_reason_code
            and intent.provider_response_content_sha256
            == authority.provider_response_content_sha256
            and intent.disclosed_images == authority.disclosed_images
            and intent.disclosed_pixels == authority.disclosed_pixels
            and intent.input_tokens == authority.input_tokens
            and intent.output_tokens == authority.output_tokens
            and intent.latency_ms == authority.latency_ms
            and intent.estimated_cost == authority.estimated_cost
        )

    @staticmethod
    def _backlog_exhaustion_receipt(
        authority: HearingBacklogRetryAuthority,
    ) -> HearingHumanReviewReceipt:
        checkpoint = authority.checkpoint
        return HearingHumanReviewReceipt(
            run_id=checkpoint.run_id,
            case_id=checkpoint.case_id,
            hearing_session_id=checkpoint.hearing_session_id,
            current_evidence_pack_id=checkpoint.current_evidence_pack_id,
            current_evidence_pack_version=checkpoint.current_evidence_pack_version,
            judge_cycle=checkpoint.judge_cycle,
            reason=HearingHumanReviewReason.HEARING_BACKLOG_EXHAUSTED,
            source_checkpoint_id=checkpoint.checkpoint_id,
            source_checkpoint_sha256=checkpoint.checkpoint_sha256,
            source_checkpoint_version=checkpoint.version,
            backlog_item_ref=ArtifactRef(
                kind=ArtifactKind.BACKLOG_ITEM,
                artifact_id=authority.item.item_id,
            ),
            manifest_id=checkpoint.manifest_id,
        )

    def _require_initial_hearing_backlog_boundary(
        self,
        connection: sqlite3.Connection,
        *,
        snapshot: CaseSnapshot,
        intent: HearingBacklogEnqueueIntent,
    ) -> None:
        item = intent.item
        checkpoint = intent.checkpoint
        request = intent.stage_request
        if (
            item.case_id != snapshot.case.case_id
            or item.manifest_id != snapshot.case.manifest_id
            or checkpoint.case_id != item.case_id
            or checkpoint.manifest_id != item.manifest_id
        ):
            raise HearingPersistenceConflict(
                "hearing backlog scope conflicts with the current Case"
            )
        latest = self._load_latest_hearing_checkpoint(
            connection,
            item.run_id,
            checkpoint.hearing_session_id,
        )
        if latest != checkpoint:
            raise ConcurrentModification(
                "hearing checkpoint changed before initial backlog enqueue"
            )
        stored_request = self._load_hearing_model_request(
            connection,
            item.run_id,
            request.request_id,
        )
        if stored_request != request or request.backlog_retry_context is not None:
            raise HearingPersistenceConflict(
                "initial backlog does not bind its exact persisted role request"
            )
        claim = connection.execute(
            """
            SELECT * FROM m4_model_call_claims
            WHERE run_id = ? AND request_id = ?
            """,
            (item.run_id, request.request_id),
        ).fetchone()
        if claim is None:
            raise RepositoryIntegrityError("hearing backlog request has no durable claim")

        provider = intent.model_call_failure
        if provider is not None:
            owner_sha256 = hashlib.sha256(provider.owner_token.encode("utf-8")).hexdigest()
            expected = (
                "ACTIVE",
                None,
                owner_sha256,
                _canonical_utc_timestamp(
                    provider.claim_lease_expires_at,
                    "hearing failure claim expiry",
                ),
                provider.claim_takeover_count,
                "INITIAL",
                None,
                0,
            )
            actual = (
                _row_str(claim, "status"),
                _row_optional_str(claim, "response_id"),
                _row_str(claim, "owner_token_sha256"),
                _row_str(claim, "lease_expires_at"),
                _row_int(claim, "takeover_count"),
                _row_str(claim, "call_generation"),
                _row_optional_str(claim, "backlog_item_id"),
                _row_int(claim, "retry_generation"),
            )
            if provider.request != request or actual != expected:
                raise ConcurrentModification(
                    "hearing provider failure no longer owns the exact active claim"
                )
            return

        proof = intent.strict_parse_failure
        assert proof is not None
        for attempt in proof.attempts:
            persisted_request = self._load_hearing_model_request(
                connection,
                item.run_id,
                attempt.request.request_id,
            )
            persisted_response = self._load_hearing_model_response(
                connection,
                item.run_id,
                attempt.response.response_id,
            )
            parse_row = connection.execute(
                """
                SELECT * FROM m4_model_parse_receipts
                WHERE run_id = ? AND parse_receipt_id = ?
                """,
                (item.run_id, attempt.parse_receipt.parse_receipt_id),
            ).fetchone()
            if parse_row is None:
                raise EvidenceMissing("strict hearing failure parse receipt is missing")
            persisted_parse = self._hearing_parse_receipt_from_row(parse_row)
            if (
                persisted_request != attempt.request
                or persisted_response != attempt.response
                or persisted_parse != attempt.parse_receipt
            ):
                raise HearingPersistenceConflict(
                    "strict hearing failure differs from its durable call history"
                )

    @staticmethod
    def _insert_hearing_backlog_item(
        connection: sqlite3.Connection,
        item: BacklogItem,
    ) -> None:
        item_json = _contract_document(item)
        item_sha256 = hashlib.sha256(item_json.encode("utf-8")).hexdigest()
        connection.execute(
            """
            INSERT INTO backlog_items(
                run_id, item_id, case_id, stage, role, reason_code,
                stage_input_kind, stage_input_id, stage_input_sha256,
                max_attempts, manifest_id, initial_json, initial_document_sha256
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
        connection.execute(
            """
            INSERT INTO backlog_item_versions(
                run_id, item_id, version, status, attempt_count,
                retry_generation, lease_id, lease_owner_sha256, lease_expires_at,
                item_json, document_sha256
            ) VALUES (?, ?, 1, ?, ?, ?, NULL, NULL, NULL, ?, ?)
            """,
            (
                item.run_id,
                item.item_id,
                item.status.value,
                item.attempt_count,
                item.retry_generation,
                item_json,
                item_sha256,
            ),
        )
        connection.execute(
            """
            INSERT INTO backlog_heads(run_id, item_id, current_version)
            VALUES (?, ?, 1)
            """,
            (item.run_id, item.item_id),
        )

    def _insert_initial_strict_parse_failure(
        self,
        connection: sqlite3.Connection,
        *,
        item: BacklogItem,
        proof: HearingInitialStrictParseFailureProof,
    ) -> None:
        for attempt in proof.attempts:
            request = attempt.request
            response = attempt.response
            parse = attempt.parse_receipt
            attempt_json = _contract_document(attempt)
            document_sha256 = hashlib.sha256(attempt_json.encode("utf-8")).hexdigest()
            connection.execute(
                """
                INSERT INTO m4_hearing_strict_parse_failure_attempts(
                    run_id, attempt_id, hearing_id, cycle_scope_id,
                    cycle_scope_sha256, case_id, role, attempt_index,
                    backlog_item_id, retry_generation,
                    request_id, request_sha256, response_id,
                    response_content_sha256, parse_receipt_id, manifest_id,
                    attempt_json, document_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    item.run_id,
                    attempt.attempt_id,
                    request.hearing_session_id,
                    request.cycle_scope_id,
                    request.cycle_scope_sha256,
                    request.case_id,
                    request.role.value,
                    request.attempt_index,
                    item.item_id,
                    request.request_id,
                    request.request_sha256,
                    response.response_id,
                    response.content_sha256,
                    parse.parse_receipt_id,
                    request.manifest_id,
                    attempt_json,
                    document_sha256,
                ),
            )
        proof_json = _contract_document(proof)
        proof_sha256 = hashlib.sha256(proof_json.encode("utf-8")).hexdigest()
        connection.execute(
            """
            INSERT INTO m4_hearing_strict_parse_failure_proofs(
                run_id, proof_id, hearing_id, case_id,
                source_checkpoint_id, source_checkpoint_sha256,
                source_checkpoint_version, backlog_item_id, closure_kind,
                lease_identity_sha256, lease_id, lease_attempt_count,
                retry_generation, role, primary_attempt_id, repair_attempt_id,
                proof_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'INITIAL_BACKLOG',
                      NULL, NULL, NULL, 0, ?, ?, ?, ?, ?)
            """,
            (
                item.run_id,
                proof.proof_id,
                proof.attempts[0].request.hearing_session_id,
                item.case_id,
                proof.source_checkpoint_id,
                proof.source_checkpoint_sha256,
                proof.source_checkpoint_version,
                item.item_id,
                proof.role.value,
                proof.attempts[0].attempt_id,
                proof.attempts[1].attempt_id,
                proof_json,
                proof_sha256,
            ),
        )

    @staticmethod
    def _insert_retry_strict_parse_failure(
        connection: sqlite3.Connection,
        proof: HearingStrictParseFailureProof,
    ) -> None:
        for attempt in proof.attempts:
            request = attempt.request
            response = attempt.response
            parse = attempt.parse_receipt
            document = _contract_document(attempt)
            connection.execute(
                """
                INSERT INTO m4_hearing_strict_parse_failure_attempts(
                    run_id, attempt_id, hearing_id, cycle_scope_id,
                    cycle_scope_sha256, case_id, role, attempt_index,
                    backlog_item_id, retry_generation,
                    request_id, request_sha256, response_id,
                    response_content_sha256, parse_receipt_id, manifest_id,
                    attempt_json, document_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    proof.lease.run_id,
                    attempt.attempt_id,
                    request.hearing_session_id,
                    request.cycle_scope_id,
                    request.cycle_scope_sha256,
                    request.case_id,
                    request.role.value,
                    request.attempt_index,
                    proof.lease.item_id,
                    proof.lease.retry_generation,
                    request.request_id,
                    request.request_sha256,
                    response.response_id,
                    response.content_sha256,
                    parse.parse_receipt_id,
                    request.manifest_id,
                    document,
                    hashlib.sha256(document.encode("utf-8")).hexdigest(),
                ),
            )
        document = _contract_document(proof)
        connection.execute(
            """
            INSERT INTO m4_hearing_strict_parse_failure_proofs(
                run_id, proof_id, hearing_id, case_id,
                source_checkpoint_id, source_checkpoint_sha256,
                source_checkpoint_version, backlog_item_id, closure_kind,
                lease_identity_sha256, lease_id, lease_attempt_count,
                retry_generation, role, primary_attempt_id, repair_attempt_id,
                proof_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'RETRY_FAILURE', ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                proof.lease.run_id,
                proof.proof_id,
                proof.attempts[0].request.hearing_session_id,
                proof.attempts[0].request.case_id,
                proof.source_checkpoint_id,
                proof.source_checkpoint_sha256,
                proof.source_checkpoint_version,
                proof.lease.item_id,
                proof.lease.lease_identity_sha256,
                proof.lease.lease_id,
                proof.lease.attempt_count,
                proof.lease.retry_generation,
                proof.role.value,
                proof.attempts[0].attempt_id,
                proof.attempts[1].attempt_id,
                document,
                hashlib.sha256(document.encode("utf-8")).hexdigest(),
            ),
        )

    @staticmethod
    def _insert_hearing_backlog_retry_outcome(
        connection: sqlite3.Connection,
        outcome: HearingBacklogRetryOutcome,
    ) -> None:
        request = outcome.request
        if isinstance(outcome, HearingBacklogRetrySuccess):
            response_id = outcome.response.response_id
            parse_receipt_id = outcome.parse_receipt.parse_receipt_id
            parsed_output_id = outcome.parsed_role_output.output_id
            next_checkpoint_id = outcome.next_checkpoint.checkpoint_id
            next_checkpoint_sha256 = outcome.next_checkpoint.checkpoint_sha256
            next_checkpoint_version = outcome.next_checkpoint.version
            reason_code = None
            next_status = None
            response_refs: tuple[ArtifactRef, ...] = ()
            proof_id = None
            human_id = (
                outcome.human_review_receipt.receipt_id
                if outcome.human_review_receipt is not None
                else None
            )
            next_retry_generation = outcome.lease.retry_generation
        else:
            response_id = None
            parse_receipt_id = None
            parsed_output_id = None
            next_checkpoint_id = None
            next_checkpoint_sha256 = None
            next_checkpoint_version = None
            reason_code = outcome.reason_code.value
            next_status = outcome.next_status.value
            response_refs = outcome.response_refs
            proof_id = (
                outcome.strict_parse_failure.proof_id
                if outcome.strict_parse_failure is not None
                else None
            )
            human_id = (
                outcome.human_review_receipt.receipt_id
                if outcome.human_review_receipt is not None
                else None
            )
            next_retry_generation = outcome.next_retry_generation
        document = _contract_document(outcome)
        connection.execute(
            """
            INSERT INTO m4_hearing_backlog_retry_outcomes(
                run_id, outcome_id, outcome_kind, hearing_id,
                cycle_scope_id, cycle_scope_sha256, case_id, role,
                backlog_item_id, lease_identity_sha256, lease_id,
                lease_attempt_count, retry_generation,
                source_checkpoint_id, source_checkpoint_sha256,
                source_checkpoint_version, request_id, request_sha256,
                response_id, parse_receipt_id, parsed_output_id,
                next_checkpoint_id, next_checkpoint_sha256,
                next_checkpoint_version, reason_code, next_status,
                response_refs_json, strict_parse_failure_proof_id,
                human_review_receipt_id, next_retry_generation,
                manifest_id, outcome_json, document_sha256
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            (
                outcome.lease.run_id,
                outcome.outcome_id,
                outcome.outcome_kind,
                request.hearing_session_id,
                request.cycle_scope_id,
                request.cycle_scope_sha256,
                request.case_id,
                request.role.value,
                outcome.lease.item_id,
                outcome.lease.lease_identity_sha256,
                outcome.lease.lease_id,
                outcome.lease.attempt_count,
                outcome.lease.retry_generation,
                outcome.source_checkpoint_id,
                outcome.source_checkpoint_sha256,
                outcome.source_checkpoint_version,
                request.request_id,
                request.request_sha256,
                response_id,
                parse_receipt_id,
                parsed_output_id,
                next_checkpoint_id,
                next_checkpoint_sha256,
                next_checkpoint_version,
                reason_code,
                next_status,
                canonical_json([ref.model_dump(mode="json") for ref in response_refs]),
                proof_id,
                human_id,
                next_retry_generation,
                outcome.manifest_id,
                document,
                hashlib.sha256(document.encode("utf-8")).hexdigest(),
            ),
        )

    @staticmethod
    def _insert_hearing_backlog_completion_receipt(
        connection: sqlite3.Connection,
        *,
        receipt: HearingBacklogCompletionReceipt,
        item: BacklogItem,
        backlog_version: int,
    ) -> None:
        outcome = receipt.outcome
        request = outcome.request
        document = _contract_document(receipt)
        connection.execute(
            """
            INSERT INTO m4_backlog_completion_receipts(
                run_id, receipt_id, receipt_sha256, item_id, case_id,
                hearing_id, role, outcome_kind, outcome_id,
                lease_identity_sha256, lease_id, attempt_count,
                retry_generation, backlog_status, backlog_version,
                source_checkpoint_id, source_checkpoint_sha256,
                source_checkpoint_version, resulting_checkpoint_id,
                resulting_checkpoint_sha256, resulting_checkpoint_version,
                completion_case_status, completion_case_revision,
                completion_audit_sequence, completion_audit_entry_hash,
                manifest_id, receipt_json, document_sha256
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?
            )
            """,
            (
                outcome.lease.run_id,
                receipt.receipt_id,
                receipt.receipt_sha256,
                outcome.lease.item_id,
                item.case_id,
                request.hearing_session_id,
                request.role.value,
                outcome.outcome_kind,
                outcome.outcome_id,
                outcome.lease.lease_identity_sha256,
                outcome.lease.lease_id,
                outcome.lease.attempt_count,
                outcome.lease.retry_generation,
                receipt.backlog_status.value,
                backlog_version,
                receipt.source_checkpoint_id,
                receipt.source_checkpoint_sha256,
                receipt.source_checkpoint_version,
                receipt.resulting_checkpoint_id,
                receipt.resulting_checkpoint_sha256,
                receipt.resulting_checkpoint_version,
                receipt.completion_case_status.value,
                receipt.completion_case_revision,
                receipt.completion_audit_sequence,
                receipt.completion_audit_entry_hash,
                receipt.manifest_id,
                document,
                hashlib.sha256(document.encode("utf-8")).hexdigest(),
            ),
        )

    def _build_initial_model_call_failure_authority(
        self,
        intent: HearingModelCallFailureIntent,
        *,
        item: BacklogItem,
        checkpoint: HearingCheckpoint,
        closure_case_revision: int,
        audit_head: AuditHead,
        recorded_at: datetime | None = None,
    ) -> HearingModelCallFailureAuthority:
        request = intent.request
        return HearingModelCallFailureAuthority(
            run_id=item.run_id,
            case_id=item.case_id,
            hearing_session_id=request.hearing_session_id,
            role=request.role,
            request=request,
            source_checkpoint_id=checkpoint.checkpoint_id,
            source_checkpoint_sha256=checkpoint.checkpoint_sha256,
            source_checkpoint_version=checkpoint.version,
            claim_owner_sha256=hashlib.sha256(intent.owner_token.encode("utf-8")).hexdigest(),
            claim_lease_expires_at=intent.claim_lease_expires_at,
            claim_takeover_count=intent.claim_takeover_count,
            failure_code=intent.failure_code,
            delivery_certainty=intent.delivery_certainty,
            provider_response_content_sha256=intent.provider_response_content_sha256,
            reserved_images=len(request.media),
            reserved_pixels=sum(media.width * media.height for media in request.media),
            disclosed_images=intent.disclosed_images,
            disclosed_pixels=intent.disclosed_pixels,
            input_tokens=intent.input_tokens,
            output_tokens=intent.output_tokens,
            latency_ms=intent.latency_ms,
            estimated_cost=intent.estimated_cost,
            backlog_reason_code=intent.backlog_reason_code,
            backlog_item_id=item.item_id,
            backlog_version=1,
            backlog_status=BacklogStatus.PENDING,
            backlog_attempt_count=0,
            retry_generation=0,
            closure_kind=ModelCallFailureClosureKind.INITIAL_BACKLOG,
            closure_case_revision=closure_case_revision,
            closure_audit_sequence=audit_head.sequence,
            closure_audit_entry_hash=audit_head.entry_hash,
            manifest_id=item.manifest_id,
            recorded_at=recorded_at
            or _parse_utc_timestamp(
                _utc_timestamp(self._host._clock),
                "hearing failure recorded_at",
            ),
        )

    def _build_retry_model_call_failure_authority(
        self,
        intent: HearingModelCallFailureIntent,
        *,
        item: BacklogItem,
        checkpoint: HearingCheckpoint,
        lease: BacklogLeaseIdentity,
        backlog_version: int,
        completion_receipt: HearingBacklogCompletionReceipt,
        closure_case_revision: int,
        audit_head: AuditHead,
        recorded_at: datetime | None = None,
    ) -> HearingModelCallFailureAuthority:
        request = intent.request
        return HearingModelCallFailureAuthority(
            run_id=item.run_id,
            case_id=item.case_id,
            hearing_session_id=request.hearing_session_id,
            role=request.role,
            request=request,
            source_checkpoint_id=checkpoint.checkpoint_id,
            source_checkpoint_sha256=checkpoint.checkpoint_sha256,
            source_checkpoint_version=checkpoint.version,
            lease=lease,
            claim_owner_sha256=hashlib.sha256(intent.owner_token.encode("utf-8")).hexdigest(),
            claim_lease_expires_at=intent.claim_lease_expires_at,
            claim_takeover_count=intent.claim_takeover_count,
            failure_code=intent.failure_code,
            delivery_certainty=intent.delivery_certainty,
            provider_response_content_sha256=intent.provider_response_content_sha256,
            reserved_images=len(request.media),
            reserved_pixels=sum(media.width * media.height for media in request.media),
            disclosed_images=intent.disclosed_images,
            disclosed_pixels=intent.disclosed_pixels,
            input_tokens=intent.input_tokens,
            output_tokens=intent.output_tokens,
            latency_ms=intent.latency_ms,
            estimated_cost=intent.estimated_cost,
            backlog_reason_code=intent.backlog_reason_code,
            backlog_item_id=item.item_id,
            backlog_version=backlog_version,
            backlog_status=item.status,
            backlog_attempt_count=item.attempt_count,
            retry_generation=lease.retry_generation,
            closure_kind=ModelCallFailureClosureKind.RETRY_FAILURE,
            completion_receipt_id=completion_receipt.receipt_id,
            closure_case_revision=closure_case_revision,
            closure_audit_sequence=audit_head.sequence,
            closure_audit_entry_hash=audit_head.entry_hash,
            manifest_id=item.manifest_id,
            recorded_at=recorded_at
            or _parse_utc_timestamp(
                _utc_timestamp(self._host._clock),
                "hearing failure recorded_at",
            ),
        )

    @staticmethod
    def _insert_model_call_failure_authority(
        connection: sqlite3.Connection,
        authority: HearingModelCallFailureAuthority,
    ) -> None:
        request = authority.request
        authority_json = _contract_document(authority)
        document_sha256 = hashlib.sha256(authority_json.encode("utf-8")).hexdigest()
        lease = authority.lease
        connection.execute(
            """
            INSERT INTO m4_model_call_failure_authorities(
                run_id, authority_id, request_id, request_sha256,
                request_document_sha256, cache_key, hearing_id,
                cycle_scope_id, cycle_scope_sha256, case_id, role,
                source_checkpoint_id, source_checkpoint_sha256,
                source_checkpoint_version, lease_identity_sha256, lease_id,
                backlog_attempt_count, retry_generation, claim_owner_sha256,
                claim_lease_expires_at, claim_takeover_count, failure_code,
                delivery_certainty, provider_response_content_sha256,
                reserved_images, reserved_pixels, disclosed_images,
                disclosed_pixels, input_tokens, output_tokens, latency_ms,
                estimated_cost, backlog_item_id, backlog_reason_code,
                backlog_version, backlog_status, closure_kind,
                completion_receipt_id, closure_case_revision,
                closure_audit_sequence, closure_audit_entry_hash, manifest_id,
                recorded_at, authority_json, document_sha256
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?
            )
            """,
            (
                authority.run_id,
                authority.authority_id,
                request.request_id,
                request.request_sha256,
                authority.request_document_sha256,
                request.cache_key,
                request.hearing_session_id,
                request.cycle_scope_id,
                request.cycle_scope_sha256,
                authority.case_id,
                authority.role.value,
                authority.source_checkpoint_id,
                authority.source_checkpoint_sha256,
                authority.source_checkpoint_version,
                lease.lease_identity_sha256 if lease is not None else None,
                lease.lease_id if lease is not None else None,
                authority.backlog_attempt_count,
                authority.retry_generation,
                authority.claim_owner_sha256,
                _canonical_utc_timestamp(
                    authority.claim_lease_expires_at,
                    "hearing failure claim expiry",
                ),
                authority.claim_takeover_count,
                authority.failure_code.value,
                authority.delivery_certainty.value,
                authority.provider_response_content_sha256,
                authority.reserved_images,
                authority.reserved_pixels,
                authority.disclosed_images,
                authority.disclosed_pixels,
                authority.input_tokens,
                authority.output_tokens,
                authority.latency_ms,
                authority.estimated_cost,
                authority.backlog_item_id,
                authority.backlog_reason_code.value,
                authority.backlog_version,
                authority.backlog_status.value,
                authority.closure_kind.value,
                authority.completion_receipt_id,
                authority.closure_case_revision,
                authority.closure_audit_sequence,
                authority.closure_audit_entry_hash,
                authority.manifest_id,
                _canonical_utc_timestamp(authority.recorded_at, "failure recorded_at"),
                authority_json,
                document_sha256,
            ),
        )

    @staticmethod
    def _audit_head_after_expected(
        connection: sqlite3.Connection,
        expected: AuditHead,
    ) -> AuditHead:
        row = connection.execute(
            """
            SELECT manifest_id, entry_hash FROM audit_entries
            WHERE run_id = ? AND sequence = ?
            """,
            (expected.run_id, expected.sequence + 1),
        ).fetchone()
        if row is None or _row_str(row, "manifest_id") != expected.manifest_id:
            raise RepositoryIntegrityError("hearing backlog audit closure is missing")
        return AuditHead(
            run_id=expected.run_id,
            manifest_id=expected.manifest_id,
            run_revision=expected.run_revision + 1,
            sequence=expected.sequence + 1,
            entry_hash=_row_str(row, "entry_hash"),
        )

    def _replay_hearing_backlog_enqueue(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        expected_case_revision: int,
        expected_audit_head: AuditHead,
        intent: HearingBacklogEnqueueIntent,
    ) -> HearingBacklogEnqueueCommit:
        item = self._load_hearing_backlog_version(
            connection,
            run_id,
            intent.item.item_id,
            1,
        )
        if item != intent.item:
            raise HearingPersistenceConflict(
                "hearing backlog identity already binds different canonical content"
            )
        checkpoint = self._load_hearing_checkpoint(
            connection,
            run_id,
            intent.checkpoint.checkpoint_id,
        )
        request = self._load_hearing_model_request(
            connection,
            run_id,
            intent.stage_request.request_id,
        )
        if checkpoint != intent.checkpoint or request != intent.stage_request:
            raise HearingPersistenceConflict(
                "hearing backlog replay changed its request or source checkpoint"
            )

        previous = self._load_case_revision(
            connection,
            run_id,
            item.case_id,
            expected_case_revision,
        )
        committed = self._load_case_revision(
            connection,
            run_id,
            item.case_id,
            expected_case_revision + 1,
        )
        assert item.role is not None
        expected_case = self._case_with_updates(
            previous.case,
            status=CaseStatus.BACKLOGGED,
            current_backlog_item_id=item.item_id,
            timeline_entry=TimelineEntry(
                sequence=len(previous.case.timeline),
                action=AuditAction.CASE_STATE_CHANGED.value,
                stage="BACKLOG",
                object_ref=item.item_id,
                details={
                    "reason_code": item.reason_code.value,
                    "retry_generation": item.retry_generation,
                    "role": item.role.value,
                    "status": CaseStatus.BACKLOGGED.value,
                },
            ),
        )
        if (
            previous.case.status != CaseStatus.DELIBERATING
            or previous.case.current_backlog_item_id is not None
            or committed.case != expected_case
        ):
            raise HearingPersistenceConflict(
                "persisted hearing backlog does not close the expected Case revision"
            )
        self._verify_transition_audit(
            connection,
            run_id=run_id,
            audit_sequence=expected_audit_head.sequence + 1,
            expected_head=expected_audit_head,
            object_id=item.item_id,
            object_kind=ArtifactKind.BACKLOG_ITEM,
        )
        audit_head = self._audit_head_after_expected(connection, expected_audit_head)

        failure_authority = None
        strict_failure = None
        provider = intent.model_call_failure
        if provider is not None:
            failure_authority = self._load_initial_model_call_failure_authority(
                connection,
                run_id,
                item.item_id,
            )
            expected_authority = self._build_initial_model_call_failure_authority(
                provider,
                item=item,
                checkpoint=checkpoint,
                closure_case_revision=committed.revision,
                audit_head=audit_head,
                recorded_at=failure_authority.recorded_at,
            )
            if failure_authority != expected_authority:
                raise HearingPersistenceConflict(
                    "hearing provider-failure replay changed its exact authority"
                )
        else:
            strict_failure = self._load_initial_strict_parse_failure(
                connection,
                run_id,
                item.item_id,
            )
            if strict_failure != intent.strict_parse_failure:
                raise HearingPersistenceConflict(
                    "initial strict-failure replay changed its exact proof"
                )
        return HearingBacklogEnqueueCommit(
            item=item,
            case=committed,
            checkpoint=checkpoint,
            stage_request=request,
            audit_head=audit_head,
            failure_authority=failure_authority,
            strict_parse_failure=strict_failure,
            created=False,
        )

    @staticmethod
    def _load_hearing_backlog_version(
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
        identity = connection.execute(
            """
            SELECT * FROM backlog_items WHERE run_id = ? AND item_id = ?
            """,
            (run_id, item_id),
        ).fetchone()
        if row is None or identity is None:
            raise EvidenceMissing("hearing backlog version is missing")
        raw = _row_str(row, "item_json")
        try:
            item = BacklogItem.model_validate_json(raw)
        except ValidationError as exc:
            raise RepositoryIntegrityError("stored hearing backlog item is invalid") from exc
        _verify_document(raw, _row_str(row, "document_sha256"), item)
        initial_raw = _row_str(identity, "initial_json")
        try:
            initial = BacklogItem.model_validate_json(initial_raw)
        except ValidationError as exc:
            raise RepositoryIntegrityError("stored hearing backlog identity is invalid") from exc
        _verify_document(
            initial_raw,
            _row_str(identity, "initial_document_sha256"),
            initial,
        )
        indexed_version = (
            _row_str(row, "run_id"),
            _row_str(row, "item_id"),
            _row_str(row, "status"),
            _row_int(row, "attempt_count"),
            _row_int(row, "retry_generation"),
            _row_optional_str(row, "lease_id"),
            _row_optional_str(row, "lease_owner_sha256"),
            _row_optional_str(row, "lease_expires_at"),
        )
        expected_version = (
            item.run_id,
            item.item_id,
            item.status.value,
            item.attempt_count,
            item.retry_generation,
            item.lease_id,
            item.lease_owner_sha256,
            (
                _canonical_utc_timestamp(item.lease_expires_at, "backlog lease expiry")
                if item.lease_expires_at is not None
                else None
            ),
        )
        indexed_identity = (
            _row_str(identity, "run_id"),
            _row_str(identity, "item_id"),
            _row_str(identity, "case_id"),
            _row_str(identity, "stage"),
            _row_optional_str(identity, "role"),
            _row_str(identity, "reason_code"),
            _row_str(identity, "stage_input_kind"),
            _row_str(identity, "stage_input_id"),
            _row_str(identity, "stage_input_sha256"),
            _row_int(identity, "max_attempts"),
            _row_str(identity, "manifest_id"),
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
        initial_identity = initial.model_copy(
            update={
                "status": item.status,
                "attempt_count": item.attempt_count,
                "retry_generation": item.retry_generation,
                "lease_id": item.lease_id,
                "lease_owner_sha256": item.lease_owner_sha256,
                "lease_expires_at": item.lease_expires_at,
            }
        )
        if (
            indexed_version != expected_version
            or indexed_identity != expected_identity
            or initial_identity != item
        ):
            raise RepositoryIntegrityError(
                "hearing backlog indexes conflict with canonical content"
            )
        return item

    def _hearing_model_failure_authority_from_row(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> HearingModelCallFailureAuthority:
        raw = _row_str(row, "authority_json")
        try:
            authority = HearingModelCallFailureAuthority.model_validate_json(raw)
        except ValidationError as exc:
            raise RepositoryIntegrityError(
                "stored hearing provider-failure authority is invalid"
            ) from exc
        _verify_document(raw, _row_str(row, "document_sha256"), authority)
        lease = authority.lease
        indexed = (
            _row_str(row, "run_id"),
            _row_str(row, "authority_id"),
            _row_str(row, "request_id"),
            _row_str(row, "request_sha256"),
            _row_str(row, "request_document_sha256"),
            _row_str(row, "cache_key"),
            _row_str(row, "hearing_id"),
            _row_str(row, "cycle_scope_id"),
            _row_str(row, "cycle_scope_sha256"),
            _row_str(row, "case_id"),
            _row_str(row, "role"),
            _row_str(row, "source_checkpoint_id"),
            _row_str(row, "source_checkpoint_sha256"),
            _row_int(row, "source_checkpoint_version"),
            _row_optional_str(row, "lease_identity_sha256"),
            _row_optional_str(row, "lease_id"),
            _row_int(row, "backlog_attempt_count"),
            _row_int(row, "retry_generation"),
            _row_str(row, "claim_owner_sha256"),
            _row_str(row, "claim_lease_expires_at"),
            _row_int(row, "claim_takeover_count"),
            _row_str(row, "failure_code"),
            _row_str(row, "delivery_certainty"),
            _row_optional_str(row, "provider_response_content_sha256"),
            _row_int(row, "reserved_images"),
            _row_int(row, "reserved_pixels"),
            _row_int(row, "disclosed_images"),
            _row_int(row, "disclosed_pixels"),
            _row_int(row, "input_tokens"),
            _row_int(row, "output_tokens"),
            _row_int(row, "latency_ms"),
            float(row["estimated_cost"]),
            _row_str(row, "backlog_item_id"),
            _row_str(row, "backlog_reason_code"),
            _row_int(row, "backlog_version"),
            _row_str(row, "backlog_status"),
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
            authority.hearing_session_id,
            authority.request.cycle_scope_id,
            authority.request.cycle_scope_sha256,
            authority.case_id,
            authority.role.value,
            authority.source_checkpoint_id,
            authority.source_checkpoint_sha256,
            authority.source_checkpoint_version,
            lease.lease_identity_sha256 if lease is not None else None,
            lease.lease_id if lease is not None else None,
            authority.backlog_attempt_count,
            authority.retry_generation,
            authority.claim_owner_sha256,
            _canonical_utc_timestamp(
                authority.claim_lease_expires_at,
                "hearing failure claim expiry",
            ),
            authority.claim_takeover_count,
            authority.failure_code.value,
            authority.delivery_certainty.value,
            authority.provider_response_content_sha256,
            authority.reserved_images,
            authority.reserved_pixels,
            authority.disclosed_images,
            authority.disclosed_pixels,
            authority.input_tokens,
            authority.output_tokens,
            authority.latency_ms,
            authority.estimated_cost,
            authority.backlog_item_id,
            authority.backlog_reason_code.value,
            authority.backlog_version,
            authority.backlog_status.value,
            authority.closure_kind.value,
            authority.completion_receipt_id,
            authority.closure_case_revision,
            authority.closure_audit_sequence,
            authority.closure_audit_entry_hash,
            authority.manifest_id,
            _canonical_utc_timestamp(authority.recorded_at, "failure recorded_at"),
        )
        if indexed != expected:
            raise RepositoryIntegrityError(
                "hearing provider-failure indexes conflict with canonical content"
            )
        persisted_request = self._load_hearing_model_request(
            connection,
            authority.run_id,
            authority.request.request_id,
        )
        if persisted_request != authority.request:
            raise RepositoryIntegrityError("hearing provider failure crosses its request authority")
        return authority

    def _load_initial_model_call_failure_authority(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        backlog_item_id: str,
    ) -> HearingModelCallFailureAuthority:
        rows = connection.execute(
            """
            SELECT * FROM m4_model_call_failure_authorities
            WHERE run_id = ? AND backlog_item_id = ?
              AND closure_kind = 'INITIAL_BACKLOG'
            """,
            (run_id, backlog_item_id),
        ).fetchall()
        if len(rows) != 1:
            raise RepositoryIntegrityError(
                "hearing backlog lacks one initial provider-failure authority"
            )
        authority = self._hearing_model_failure_authority_from_row(
            connection,
            rows[0],
        )
        if authority.closure_kind != ModelCallFailureClosureKind.INITIAL_BACKLOG:
            raise RepositoryIntegrityError(
                "initial hearing provider failure has the wrong closure kind"
            )
        return authority

    def _load_retry_model_call_failure_authority(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        completion_receipt_id: str,
    ) -> HearingModelCallFailureAuthority | None:
        rows = connection.execute(
            """
            SELECT * FROM m4_model_call_failure_authorities
            WHERE run_id = ? AND completion_receipt_id = ?
              AND closure_kind = 'RETRY_FAILURE'
            """,
            (run_id, completion_receipt_id),
        ).fetchall()
        if not rows:
            return None
        if len(rows) != 1:
            raise RepositoryIntegrityError(
                "hearing completion selects multiple provider failure authorities"
            )
        row = rows[0]
        raw = _row_str(row, "authority_json")
        try:
            authority = HearingModelCallFailureAuthority.model_validate_json(raw)
        except ValidationError as exc:
            raise RepositoryIntegrityError(
                "stored hearing retry provider-failure authority is invalid"
            ) from exc
        _verify_document(raw, _row_str(row, "document_sha256"), authority)
        lease = authority.lease
        if lease is None:
            raise RepositoryIntegrityError("retry provider failure lacks its lease")
        indexed = (
            _row_str(row, "run_id"),
            _row_str(row, "authority_id"),
            _row_str(row, "request_id"),
            _row_str(row, "request_sha256"),
            _row_str(row, "request_document_sha256"),
            _row_str(row, "cache_key"),
            _row_str(row, "hearing_id"),
            _row_str(row, "cycle_scope_id"),
            _row_str(row, "cycle_scope_sha256"),
            _row_str(row, "case_id"),
            _row_str(row, "role"),
            _row_str(row, "source_checkpoint_id"),
            _row_str(row, "source_checkpoint_sha256"),
            _row_int(row, "source_checkpoint_version"),
            _row_str(row, "lease_identity_sha256"),
            _row_str(row, "lease_id"),
            _row_int(row, "backlog_attempt_count"),
            _row_int(row, "retry_generation"),
            _row_str(row, "claim_owner_sha256"),
            _row_str(row, "claim_lease_expires_at"),
            _row_int(row, "claim_takeover_count"),
            _row_str(row, "failure_code"),
            _row_str(row, "delivery_certainty"),
            _row_optional_str(row, "provider_response_content_sha256"),
            _row_int(row, "reserved_images"),
            _row_int(row, "reserved_pixels"),
            _row_int(row, "disclosed_images"),
            _row_int(row, "disclosed_pixels"),
            _row_int(row, "input_tokens"),
            _row_int(row, "output_tokens"),
            _row_int(row, "latency_ms"),
            float(row["estimated_cost"]),
            _row_str(row, "backlog_item_id"),
            _row_str(row, "backlog_reason_code"),
            _row_int(row, "backlog_version"),
            _row_str(row, "backlog_status"),
            _row_str(row, "closure_kind"),
            _row_str(row, "completion_receipt_id"),
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
            authority.hearing_session_id,
            authority.request.cycle_scope_id,
            authority.request.cycle_scope_sha256,
            authority.case_id,
            authority.role.value,
            authority.source_checkpoint_id,
            authority.source_checkpoint_sha256,
            authority.source_checkpoint_version,
            lease.lease_identity_sha256,
            lease.lease_id,
            authority.backlog_attempt_count,
            authority.retry_generation,
            authority.claim_owner_sha256,
            _canonical_utc_timestamp(
                authority.claim_lease_expires_at,
                "hearing failure claim expiry",
            ),
            authority.claim_takeover_count,
            authority.failure_code.value,
            authority.delivery_certainty.value,
            authority.provider_response_content_sha256,
            authority.reserved_images,
            authority.reserved_pixels,
            authority.disclosed_images,
            authority.disclosed_pixels,
            authority.input_tokens,
            authority.output_tokens,
            authority.latency_ms,
            authority.estimated_cost,
            authority.backlog_item_id,
            authority.backlog_reason_code.value,
            authority.backlog_version,
            authority.backlog_status.value,
            authority.closure_kind.value,
            authority.completion_receipt_id,
            authority.closure_case_revision,
            authority.closure_audit_sequence,
            authority.closure_audit_entry_hash,
            authority.manifest_id,
            _canonical_utc_timestamp(authority.recorded_at, "failure recorded_at"),
        )
        if indexed != expected:
            raise RepositoryIntegrityError(
                "hearing retry provider-failure indexes conflict with canonical content"
            )
        persisted_request = self._load_hearing_model_request(
            connection,
            run_id,
            authority.request.request_id,
        )
        if persisted_request != authority.request:
            raise RepositoryIntegrityError(
                "hearing retry provider failure crosses its request authority"
            )
        return authority

    @staticmethod
    def _load_initial_strict_parse_failure(
        connection: sqlite3.Connection,
        run_id: str,
        backlog_item_id: str,
    ) -> HearingInitialStrictParseFailureProof:
        rows = connection.execute(
            """
            SELECT * FROM m4_hearing_strict_parse_failure_proofs
            WHERE run_id = ? AND backlog_item_id = ?
              AND closure_kind = 'INITIAL_BACKLOG'
            """,
            (run_id, backlog_item_id),
        ).fetchall()
        if len(rows) != 1:
            raise RepositoryIntegrityError("hearing backlog lacks one initial strict-failure proof")
        row = rows[0]
        raw = _row_str(row, "proof_json")
        try:
            proof = HearingInitialStrictParseFailureProof.model_validate_json(raw)
        except ValidationError as exc:
            raise RepositoryIntegrityError(
                "stored initial strict-failure proof is invalid"
            ) from exc
        _verify_document(raw, _row_str(row, "document_sha256"), proof)
        if (
            _row_str(row, "proof_id") != proof.proof_id
            or _row_str(row, "backlog_item_id") != proof.backlog_item_id
            or _row_str(row, "source_checkpoint_id") != proof.source_checkpoint_id
            or _row_str(row, "source_checkpoint_sha256") != proof.source_checkpoint_sha256
            or _row_int(row, "source_checkpoint_version") != proof.source_checkpoint_version
            or _row_str(row, "role") != proof.role.value
            or _row_int(row, "retry_generation") != 0
            or _row_optional_str(row, "lease_identity_sha256") is not None
            or _row_optional_str(row, "lease_id") is not None
            or row["lease_attempt_count"] is not None
            or _row_str(row, "primary_attempt_id") != proof.attempts[0].attempt_id
            or _row_str(row, "repair_attempt_id") != proof.attempts[1].attempt_id
        ):
            raise RepositoryIntegrityError(
                "initial strict-failure indexes conflict with canonical proof"
            )
        for attempt in proof.attempts:
            attempt_row = connection.execute(
                """
                SELECT attempt_json, document_sha256
                FROM m4_hearing_strict_parse_failure_attempts
                WHERE run_id = ? AND attempt_id = ?
                """,
                (run_id, attempt.attempt_id),
            ).fetchone()
            if attempt_row is None:
                raise RepositoryIntegrityError(
                    "initial strict-failure proof lacks one exact attempt"
                )
            attempt_raw = _row_str(attempt_row, "attempt_json")
            try:
                persisted = HearingStrictParseFailureAttempt.model_validate_json(attempt_raw)
            except ValidationError as exc:
                raise RepositoryIntegrityError("stored strict-failure attempt is invalid") from exc
            _verify_document(
                attempt_raw,
                _row_str(attempt_row, "document_sha256"),
                persisted,
            )
            if persisted != attempt:
                raise RepositoryIntegrityError("initial strict-failure proof and attempt differ")
        return proof

    @staticmethod
    def _require_expected_case_revision(expected_case_revision: int) -> None:
        if (
            not isinstance(expected_case_revision, int)
            or isinstance(expected_case_revision, bool)
            or expected_case_revision < 1
        ):
            raise ValueError("expected_case_revision must be a positive integer")

    @staticmethod
    def _require_expected_head(actual: AuditHead, expected: AuditHead) -> None:
        if not isinstance(expected, AuditHead):
            raise TypeError("expected_audit_head must be an AuditHead")
        if actual != expected:
            raise ConcurrentModification("run audit head changed before M4 transaction")

    @staticmethod
    def _case_with_updates(
        case: Case,
        *,
        status: CaseStatus,
        timeline_entry: TimelineEntry,
        verdicts: tuple[Verdict, ...] | None = None,
        procedural_reviews: tuple[ProceduralReview, ...] | None = None,
        evidence_packs: tuple[EvidencePack, ...] | None = None,
        current_backlog_item_id: str | None = None,
    ) -> Case:
        payload = case.model_dump(mode="json", exclude_computed_fields=True)
        payload["status"] = status.value
        payload["current_backlog_item_id"] = current_backlog_item_id
        payload["timeline"] = [
            *(entry.model_dump(mode="json") for entry in case.timeline),
            timeline_entry.model_dump(mode="json"),
        ]
        if verdicts is not None:
            payload["verdicts"] = [item.model_dump(mode="json") for item in verdicts]
        if procedural_reviews is not None:
            payload["procedural_reviews"] = [
                item.model_dump(mode="json") for item in procedural_reviews
            ]
        if evidence_packs is not None:
            payload["evidence_packs"] = [item.model_dump(mode="json") for item in evidence_packs]
        try:
            return Case.model_validate(payload)
        except ValidationError as exc:
            raise ContractViolation("M4 Case transition violates aggregate invariants") from exc

    def _commit_case_version(
        self,
        connection: sqlite3.Connection,
        *,
        previous: CaseSnapshot,
        previous_document_sha256: str,
        new_case: Case,
        expected_head: AuditHead,
        object_ref: ArtifactRef,
        fault_prefix: str,
        audit_action: AuditAction = AuditAction.CASE_STATE_CHANGED,
        latest_pack_id: str | None = None,
        latest_pack_version: int | None = None,
    ) -> CaseSnapshot:
        if (latest_pack_id is None) != (latest_pack_version is None):
            raise ValueError("latest pack ID and version must be supplied together")
        case_json = _contract_document(new_case)
        case_sha256 = hashlib.sha256(case_json.encode("utf-8")).hexdigest()
        audit, _ = self._host._append_audit(
            connection,
            expected_head,
            action=audit_action,
            object_ref=object_ref,
            before_sha256=previous_document_sha256,
            after_sha256=case_sha256,
            actor=AuditActorRole.SYSTEM,
        )
        self._host._fault(f"{fault_prefix}.after_audit")
        new_revision = previous.revision + 1
        connection.execute(
            """
            INSERT INTO case_versions(
                run_id, case_id, revision, status,
                case_json, document_sha256, audit_sequence
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                new_case.run_id,
                new_case.case_id,
                new_revision,
                new_case.status.value,
                case_json,
                case_sha256,
                audit.sequence,
            ),
        )
        self._host._fault(f"{fault_prefix}.after_case_version")
        if latest_pack_id is None:
            cursor = connection.execute(
                """
                UPDATE cases
                SET status = ?, current_revision = ?
                WHERE run_id = ? AND case_id = ? AND current_revision = ?
                """,
                (
                    new_case.status.value,
                    new_revision,
                    new_case.run_id,
                    new_case.case_id,
                    previous.revision,
                ),
            )
        else:
            cursor = connection.execute(
                """
                UPDATE cases
                SET status = ?, current_revision = ?,
                    latest_pack_id = ?, latest_pack_version = ?
                WHERE run_id = ? AND case_id = ? AND current_revision = ?
                """,
                (
                    new_case.status.value,
                    new_revision,
                    latest_pack_id,
                    latest_pack_version,
                    new_case.run_id,
                    new_case.case_id,
                    previous.revision,
                ),
            )
        if cursor.rowcount != 1:
            raise ConcurrentModification("case revision changed during M4 transaction")
        self._host._fault(f"{fault_prefix}.after_case_update")
        return CaseSnapshot(case=new_case, revision=new_revision)

    @staticmethod
    def _load_case_revision(
        connection: sqlite3.Connection,
        run_id: str,
        case_id: str,
        revision: int,
    ) -> CaseSnapshot:
        row = connection.execute(
            """
            SELECT status, case_json, document_sha256
            FROM case_versions
            WHERE run_id = ? AND case_id = ? AND revision = ?
            """,
            (run_id, case_id, revision),
        ).fetchone()
        if row is None:
            raise HearingPersistenceConflict("persisted M4 root lacks its exact Case revision")
        raw = _row_str(row, "case_json")
        try:
            case = Case.model_validate_json(raw)
        except ValidationError as exc:
            raise RepositoryIntegrityError("stored M4 Case revision is invalid") from exc
        _verify_document(raw, _row_str(row, "document_sha256"), case)
        if (
            case.run_id != run_id
            or case.case_id != case_id
            or case.status.value != _row_str(row, "status")
        ):
            raise RepositoryIntegrityError("M4 Case revision indexes conflict with content")
        return CaseSnapshot(case=case, revision=revision)

    @staticmethod
    def _verify_transition_audit(
        connection: sqlite3.Connection,
        *,
        run_id: str,
        audit_sequence: int,
        expected_head: AuditHead,
        object_id: str,
        object_kind: ArtifactKind,
        action: AuditAction = AuditAction.CASE_STATE_CHANGED,
    ) -> None:
        if (
            expected_head.run_id != run_id
            or expected_head.run_revision != expected_head.sequence + 1
            or audit_sequence != expected_head.sequence + 1
        ):
            raise HearingPersistenceConflict(
                "persisted M4 roots do not bind a well-formed expected audit CAS"
            )
        row = connection.execute(
            """
            SELECT manifest_id, action, object_kind, object_id, prev_entry_hash
            FROM audit_entries
            WHERE run_id = ? AND sequence = ?
            """,
            (run_id, audit_sequence),
        ).fetchone()
        if row is None or (
            _row_str(row, "manifest_id") != expected_head.manifest_id
            or _row_str(row, "action") != action.value
            or _row_str(row, "object_kind") != object_kind.value
            or _row_str(row, "object_id") != object_id
            or _row_str(row, "prev_entry_hash") != expected_head.entry_hash
        ):
            raise HearingPersistenceConflict(
                "persisted M4 roots do not bind the expected audit CAS"
            )

    def _load_latest_hearing_checkpoint(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        hearing_id: str,
    ) -> HearingCheckpoint:
        checkpoints = self._list_hearing_checkpoints(connection, run_id, hearing_id)
        if not checkpoints:
            raise EvidenceMissing("hearing has no persisted checkpoint")
        return checkpoints[-1]

    def _list_hearing_checkpoints(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        hearing_id: str,
    ) -> tuple[HearingCheckpoint, ...]:
        rows = connection.execute(
            """
            SELECT checkpoint_id
            FROM m4_hearing_checkpoints
            WHERE run_id = ? AND hearing_id = ?
            ORDER BY version
            """,
            (run_id, hearing_id),
        ).fetchall()
        checkpoints = tuple(
            self._load_hearing_checkpoint(
                connection,
                run_id,
                _row_str(row, "checkpoint_id"),
            )
            for row in rows
        )
        if tuple(item.version for item in checkpoints) != tuple(range(1, len(checkpoints) + 1)):
            raise RepositoryIntegrityError("hearing checkpoint history is not contiguous")
        for previous, current in pairwise(checkpoints):
            if (
                current.previous_checkpoint_id != previous.checkpoint_id
                or current.previous_checkpoint_sha256 != previous.checkpoint_sha256
                or current.previous_phase != previous.phase
            ):
                raise RepositoryIntegrityError("hearing checkpoint history has a split head")
        return checkpoints

    def _list_hearing_rounds(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        hearing_id: str,
    ) -> tuple[HearingRound, ...]:
        rows = connection.execute(
            """
            SELECT round_id FROM m4_hearing_rounds
            WHERE run_id = ? AND hearing_id = ?
            ORDER BY round_index
            """,
            (run_id, hearing_id),
        ).fetchall()
        rounds = tuple(
            self._load_hearing_round(connection, run_id, _row_str(row, "round_id")) for row in rows
        )
        if tuple(item.round_index for item in rounds) != tuple(range(1, len(rounds) + 1)):
            raise RepositoryIntegrityError("hearing round history is not contiguous")
        return rounds

    @staticmethod
    def _insert_verdict_review_roots(
        connection: sqlite3.Connection,
        verdict: Verdict,
        review: ProceduralReview,
        *,
        audit_sequence: int,
    ) -> None:
        verdict_json = _contract_document(verdict)
        verdict_document_sha256 = hashlib.sha256(verdict_json.encode("utf-8")).hexdigest()
        review_json = _contract_document(review)
        review_document_sha256 = hashlib.sha256(review_json.encode("utf-8")).hexdigest()
        connection.execute(
            """
            INSERT INTO verdicts(
                run_id, verdict_id, case_id, version, screening_id,
                evidence_pack_id, evidence_pack_version,
                verdict_input_sha256, verdict_sha256,
                manifest_id, audit_sequence, verdict_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                verdict.run_id,
                verdict.verdict_id,
                verdict.case_id,
                verdict.version,
                verdict.screening_id,
                verdict.evidence_pack_id,
                verdict.evidence_pack_version,
                verdict.verdict_input_sha256,
                verdict.verdict_sha256,
                verdict.manifest_id,
                audit_sequence,
                verdict_json,
                verdict_document_sha256,
            ),
        )
        connection.execute(
            """
            INSERT INTO procedural_reviews(
                run_id, review_id, case_id, version,
                evidence_pack_id, evidence_pack_version,
                reviewed_verdict_id, reviewed_verdict_version,
                reviewed_verdict_sha256, passed, manifest_id,
                audit_sequence, review_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                review.run_id,
                review.review_id,
                review.case_id,
                review.version,
                review.evidence_pack_id,
                review.evidence_pack_version,
                review.reviewed_verdict_id,
                review.reviewed_verdict_version,
                review.reviewed_verdict_sha256,
                int(review.passed),
                review.manifest_id,
                audit_sequence,
                review_json,
                review_document_sha256,
            ),
        )
        SQLiteHearingRepository._insert_procedural_defects(
            connection,
            run_id=review.run_id,
            owner_id=review.review_id,
            defects=review.defects,
        )

    @staticmethod
    def _insert_procedural_defects(
        connection: sqlite3.Connection,
        *,
        run_id: str,
        owner_id: str,
        defects: tuple[ProceduralDefect, ...],
    ) -> None:
        for ordinal, defect in enumerate(defects):
            defect_json = _contract_document(defect)
            document_sha256 = hashlib.sha256(defect_json.encode("utf-8")).hexdigest()
            connection.execute(
                """
                INSERT INTO procedural_defects(
                    run_id, owner_kind, owner_id, ordinal, defect_id,
                    origin, code, artifact_kind, artifact_id,
                    parse_receipt_id, review_id,
                    defect_json, document_sha256
                ) VALUES (?, 'PROCEDURAL_REVIEW', ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?)
                """,
                (
                    run_id,
                    owner_id,
                    ordinal,
                    defect.defect_id,
                    defect.origin.value,
                    defect.code.value,
                    defect.artifact_ref.kind.value,
                    defect.artifact_ref.artifact_id,
                    owner_id,
                    defect_json,
                    document_sha256,
                ),
            )

    @staticmethod
    def _insert_hearing_verdict_binding(
        connection: sqlite3.Connection,
        binding: HearingVerdictBinding,
        *,
        cycle_scope_id: str,
        cycle_scope_sha256: str,
    ) -> None:
        document = _contract_document(binding)
        document_sha256 = hashlib.sha256(document.encode("utf-8")).hexdigest()
        connection.execute(
            """
            INSERT INTO m4_hearing_verdict_bindings(
                run_id, binding_id, hearing_id,
                hearing_record_id, hearing_record_version, hearing_record_sha256,
                cycle_scope_id, cycle_scope_sha256,
                round_id, judge_round_index, case_id,
                evidence_pack_id, evidence_pack_version,
                verdict_id, verdict_version, verdict_input_sha256, verdict_sha256,
                prosecutor_output_id, defender_output_id, judge_output_id,
                model_request_refs_json, model_response_refs_json,
                parse_receipt_refs_json, manifest_id, binding_json, document_sha256
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?
            )
            """,
            (
                binding.run_id,
                binding.binding_id,
                binding.hearing_session_id,
                binding.hearing_record_id,
                binding.hearing_record_version,
                binding.hearing_record_sha256,
                cycle_scope_id,
                cycle_scope_sha256,
                binding.judge_round_id,
                binding.judge_round_index,
                binding.case_id,
                binding.evidence_pack_id,
                binding.evidence_pack_version,
                binding.verdict_id,
                binding.verdict_version,
                binding.verdict_input_sha256,
                binding.verdict_sha256,
                binding.prosecutor_output_id,
                binding.defender_output_id,
                binding.judge_output_id,
                canonical_json([ref.model_dump(mode="json") for ref in binding.model_request_refs]),
                canonical_json(
                    [ref.model_dump(mode="json") for ref in binding.model_response_refs]
                ),
                canonical_json([ref.model_dump(mode="json") for ref in binding.parse_receipt_refs]),
                binding.manifest_id,
                document,
                document_sha256,
            ),
        )

    @staticmethod
    def _insert_hearing_rework_receipt(
        connection: sqlite3.Connection,
        receipt: HearingReworkReceipt,
    ) -> None:
        document = _contract_document(receipt)
        document_sha256 = hashlib.sha256(document.encode("utf-8")).hexdigest()
        connection.execute(
            """
            INSERT INTO m4_rework_receipts(
                run_id, rework_receipt_id, hearing_id, case_id,
                failed_review_id, prior_round_id,
                next_cycle_scope_id, next_cycle_scope_sha256,
                rework_index, defect_set_sha256, defect_codes_json,
                prompt_defect_summary_sha256, manifest_id,
                receipt_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                receipt.run_id,
                receipt.receipt_id,
                receipt.hearing_session_id,
                receipt.case_id,
                receipt.failed_review_id,
                receipt.prior_round_id,
                receipt.next_cycle_scope_id,
                receipt.next_cycle_scope_sha256,
                receipt.rework_index,
                receipt.defect_set_sha256,
                canonical_json([code.value for code in receipt.defect_codes]),
                receipt.prompt_defect_summary_sha256,
                receipt.manifest_id,
                document,
                document_sha256,
            ),
        )

    def _load_hearing_rework_receipt(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        receipt_id: str,
    ) -> HearingReworkReceipt:
        row = connection.execute(
            """
            SELECT * FROM m4_rework_receipts
            WHERE run_id = ? AND rework_receipt_id = ?
            """,
            (run_id, receipt_id),
        ).fetchone()
        if row is None:
            raise EvidenceMissing("hearing rework receipt authority is absent")
        raw = _row_str(row, "receipt_json")
        try:
            receipt = HearingReworkReceipt.model_validate_json(raw)
        except ValidationError as exc:
            raise RepositoryIntegrityError("stored hearing rework receipt is invalid") from exc
        _verify_document(raw, _row_str(row, "document_sha256"), receipt)
        if (
            receipt.run_id != run_id
            or receipt.receipt_id != receipt_id
            or receipt.hearing_session_id != _row_str(row, "hearing_id")
            or receipt.case_id != _row_str(row, "case_id")
            or receipt.failed_review_id != _row_str(row, "failed_review_id")
            or receipt.prior_round_id != _row_str(row, "prior_round_id")
            or receipt.next_cycle_scope_id != _row_str(row, "next_cycle_scope_id")
            or receipt.next_cycle_scope_sha256 != _row_str(row, "next_cycle_scope_sha256")
            or receipt.rework_index != _row_int(row, "rework_index")
            or receipt.defect_set_sha256 != _row_str(row, "defect_set_sha256")
            or receipt.manifest_id != _row_str(row, "manifest_id")
        ):
            raise RepositoryIntegrityError("hearing rework receipt indexes conflict with content")
        return receipt

    @staticmethod
    def _insert_hearing_human_review_receipt(
        connection: sqlite3.Connection,
        receipt: HearingHumanReviewReceipt,
    ) -> None:
        document = _contract_document(receipt)
        document_sha256 = hashlib.sha256(document.encode("utf-8")).hexdigest()
        connection.execute(
            """
            INSERT INTO m4_hearing_human_review_receipts(
                run_id, receipt_id, receipt_sha256, hearing_id, case_id,
                current_pack_id, current_pack_version, judge_cycle, reason,
                source_checkpoint_id, source_checkpoint_sha256,
                source_checkpoint_version, procedural_review_id,
                backlog_item_id, acquisition_model_request_id,
                manifest_id, receipt_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                receipt.run_id,
                receipt.receipt_id,
                receipt.receipt_sha256,
                receipt.hearing_session_id,
                receipt.case_id,
                receipt.current_evidence_pack_id,
                receipt.current_evidence_pack_version,
                receipt.judge_cycle,
                receipt.reason.value,
                receipt.source_checkpoint_id,
                receipt.source_checkpoint_sha256,
                receipt.source_checkpoint_version,
                (
                    receipt.procedural_review_ref.artifact_id
                    if receipt.procedural_review_ref is not None
                    else None
                ),
                (
                    receipt.backlog_item_ref.artifact_id
                    if receipt.backlog_item_ref is not None
                    else None
                ),
                (
                    receipt.acquisition_request_ref.artifact_id
                    if receipt.acquisition_request_ref is not None
                    else None
                ),
                receipt.manifest_id,
                document,
                document_sha256,
            ),
        )

    def _load_hearing_human_review_receipt(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        receipt_id: str,
    ) -> HearingHumanReviewReceipt:
        row = connection.execute(
            """
            SELECT * FROM m4_hearing_human_review_receipts
            WHERE run_id = ? AND receipt_id = ?
            """,
            (run_id, receipt_id),
        ).fetchone()
        if row is None:
            raise EvidenceMissing("hearing human-review receipt authority is absent")
        raw = _row_str(row, "receipt_json")
        try:
            receipt = HearingHumanReviewReceipt.model_validate_json(raw)
        except ValidationError as exc:
            raise RepositoryIntegrityError(
                "stored hearing human-review receipt is invalid"
            ) from exc
        _verify_document(raw, _row_str(row, "document_sha256"), receipt)
        if (
            receipt.run_id != run_id
            or receipt.receipt_id != receipt_id
            or receipt.receipt_sha256 != _row_str(row, "receipt_sha256")
            or receipt.hearing_session_id != _row_str(row, "hearing_id")
            or receipt.case_id != _row_str(row, "case_id")
            or receipt.current_evidence_pack_id != _row_str(row, "current_pack_id")
            or receipt.current_evidence_pack_version != _row_int(row, "current_pack_version")
            or receipt.judge_cycle != _row_int(row, "judge_cycle")
            or receipt.reason.value != _row_str(row, "reason")
            or receipt.source_checkpoint_id != _row_str(row, "source_checkpoint_id")
            or receipt.source_checkpoint_sha256 != _row_str(row, "source_checkpoint_sha256")
            or receipt.source_checkpoint_version != _row_int(row, "source_checkpoint_version")
            or receipt.manifest_id != _row_str(row, "manifest_id")
        ):
            raise RepositoryIntegrityError(
                "hearing human-review receipt indexes conflict with content"
            )
        return receipt

    def _load_verdict(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        verdict_id: str,
    ) -> Verdict:
        row = connection.execute(
            "SELECT * FROM verdicts WHERE run_id = ? AND verdict_id = ?",
            (run_id, verdict_id),
        ).fetchone()
        if row is None:
            raise EvidenceMissing("hearing Verdict authority is absent")
        raw = _row_str(row, "verdict_json")
        try:
            verdict = Verdict.model_validate_json(raw)
        except ValidationError as exc:
            raise RepositoryIntegrityError("stored hearing Verdict is invalid") from exc
        _verify_document(raw, _row_str(row, "document_sha256"), verdict)
        if (
            verdict.run_id != run_id
            or verdict.verdict_id != verdict_id
            or verdict.case_id != _row_str(row, "case_id")
            or verdict.version != _row_int(row, "version")
            or verdict.verdict_input_sha256 != _row_str(row, "verdict_input_sha256")
            or verdict.verdict_sha256 != _row_str(row, "verdict_sha256")
        ):
            raise RepositoryIntegrityError("hearing Verdict indexes conflict with content")
        return verdict

    def _load_procedural_review(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        review_id: str,
    ) -> ProceduralReview:
        row = connection.execute(
            "SELECT * FROM procedural_reviews WHERE run_id = ? AND review_id = ?",
            (run_id, review_id),
        ).fetchone()
        if row is None:
            raise EvidenceMissing("hearing procedural review authority is absent")
        raw = _row_str(row, "review_json")
        try:
            review = ProceduralReview.model_validate_json(raw)
        except ValidationError as exc:
            raise RepositoryIntegrityError("stored hearing procedural review is invalid") from exc
        _verify_document(raw, _row_str(row, "document_sha256"), review)
        defect_rows = connection.execute(
            """
            SELECT defect_json, document_sha256
            FROM procedural_defects
            WHERE run_id = ? AND owner_kind = 'PROCEDURAL_REVIEW' AND owner_id = ?
            ORDER BY ordinal
            """,
            (run_id, review_id),
        ).fetchall()
        defects: list[ProceduralDefect] = []
        for defect_row in defect_rows:
            defect_raw = _row_str(defect_row, "defect_json")
            try:
                defect = ProceduralDefect.model_validate_json(defect_raw)
            except ValidationError as exc:
                raise RepositoryIntegrityError("stored procedural defect is invalid") from exc
            _verify_document(
                defect_raw,
                _row_str(defect_row, "document_sha256"),
                defect,
            )
            defects.append(defect)
        if (
            review.run_id != run_id
            or review.review_id != review_id
            or review.case_id != _row_str(row, "case_id")
            or review.version != _row_int(row, "version")
            or int(review.passed) != _row_int(row, "passed")
            or tuple(defects) != review.defects
        ):
            raise RepositoryIntegrityError(
                "hearing procedural review indexes conflict with content"
            )
        return review

    def _load_hearing_verdict_binding(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        binding_id: str,
    ) -> HearingVerdictBinding:
        row = connection.execute(
            """
            SELECT * FROM m4_hearing_verdict_bindings
            WHERE run_id = ? AND binding_id = ?
            """,
            (run_id, binding_id),
        ).fetchone()
        if row is None:
            raise EvidenceMissing("hearing Verdict binding authority is absent")
        raw = _row_str(row, "binding_json")
        try:
            binding = HearingVerdictBinding.model_validate_json(raw)
        except ValidationError as exc:
            raise RepositoryIntegrityError("stored hearing Verdict binding is invalid") from exc
        _verify_document(raw, _row_str(row, "document_sha256"), binding)
        if (
            binding.run_id != run_id
            or binding.binding_id != binding_id
            or binding.hearing_session_id != _row_str(row, "hearing_id")
            or binding.hearing_record_id != _row_str(row, "hearing_record_id")
            or binding.hearing_record_version != _row_int(row, "hearing_record_version")
            or binding.hearing_record_sha256 != _row_str(row, "hearing_record_sha256")
            or binding.judge_round_id != _row_str(row, "round_id")
            or binding.judge_round_index != _row_int(row, "judge_round_index")
            or binding.case_id != _row_str(row, "case_id")
            or binding.verdict_id != _row_str(row, "verdict_id")
            or binding.verdict_version != _row_int(row, "verdict_version")
        ):
            raise RepositoryIntegrityError("hearing Verdict binding indexes conflict with content")
        return binding

    def _insert_hearing_session(
        self,
        connection: sqlite3.Connection,
        session: HearingSession,
    ) -> None:
        screening = connection.execute(
            """
            SELECT audit_sequence
            FROM screening_results
            WHERE run_id = ? AND screening_id = ? AND case_id = ?
              AND evidence_pack_id = ? AND evidence_pack_version = ?
              AND manifest_id = ?
            """,
            (
                session.run_id,
                session.screening_id,
                session.case_id,
                session.initial_evidence_pack_id,
                session.initial_evidence_pack_version,
                session.manifest_id,
            ),
        ).fetchone()
        if screening is None:
            raise EvidenceMissing("hearing session screening authority is absent")
        connection.execute(
            """
            INSERT INTO m4_hearings(
                run_id, hearing_id, case_id, screening_id, entry_status,
                trigger_review_id, initial_defect_codes_json,
                initial_pack_id, initial_pack_version,
                max_acquisition_rounds, max_rework_rounds,
                max_total_images, max_total_output_tokens, max_judge_cycles,
                hearing_prompt_bundle_sha256,
                prosecutor_model_manifest_id, defender_model_manifest_id,
                judge_model_manifest_id, manifest_id, created_audit_sequence,
                hearing_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session.run_id,
                session.session_id,
                session.case_id,
                session.screening_id,
                session.entry_status.value,
                (
                    session.initial_trigger_review_ref.artifact_id
                    if session.initial_trigger_review_ref is not None
                    else None
                ),
                canonical_json([code.value for code in session.initial_defect_codes]),
                session.initial_evidence_pack_id,
                session.initial_evidence_pack_version,
                session.acquisition_round_limit,
                session.rework_round_limit,
                session.max_total_images,
                session.max_total_output_tokens,
                session.max_total_judge_cycles,
                session.hearing_prompt_bundle_sha256,
                session.prosecutor_model_manifest_id,
                session.defender_model_manifest_id,
                session.judge_model_manifest_id,
                session.manifest_id,
                _row_int(screening, "audit_sequence"),
                _contract_document(session),
                session.session_sha256,
            ),
        )

    def _insert_hearing_cycle(
        self,
        connection: sqlite3.Connection,
        cycle: HearingCycleScope,
    ) -> None:
        hearing = connection.execute(
            """
            SELECT created_audit_sequence
            FROM m4_hearings
            WHERE run_id = ? AND hearing_id = ? AND case_id = ?
            """,
            (cycle.run_id, cycle.hearing_session_id, cycle.case_id),
        ).fetchone()
        if hearing is None:
            raise EvidenceMissing("hearing cycle session authority is absent")
        connection.execute(
            """
            INSERT INTO m4_hearing_cycles(
                run_id, cycle_id, cycle_sha256, hearing_id, case_id,
                cycle_index, prior_acquisition_rounds, prior_rework_rounds,
                cycle_pack_id, cycle_pack_version,
                initial_trigger_review_id, initial_defect_codes_json,
                rework_review_id, rework_defect_codes_json,
                manifest_id, created_audit_sequence, cycle_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                cycle.run_id,
                cycle.cycle_id,
                cycle.cycle_sha256,
                cycle.hearing_session_id,
                cycle.case_id,
                cycle.cycle_index,
                cycle.prior_acquisition_rounds,
                cycle.prior_rework_rounds,
                cycle.cycle_evidence_pack_id,
                cycle.cycle_evidence_pack_version,
                (
                    cycle.initial_trigger_review_ref.artifact_id
                    if cycle.initial_trigger_review_ref is not None
                    else None
                ),
                canonical_json([code.value for code in cycle.initial_defect_codes]),
                (
                    cycle.rework_review_ref.artifact_id
                    if cycle.rework_review_ref is not None
                    else None
                ),
                canonical_json([code.value for code in cycle.rework_defect_codes]),
                cycle.manifest_id,
                _row_int(hearing, "created_audit_sequence"),
                _contract_document(cycle),
            ),
        )

    def _insert_hearing_checkpoint(
        self,
        connection: sqlite3.Connection,
        checkpoint: HearingCheckpoint,
    ) -> None:
        retrieval = checkpoint.precedent_retrieval_receipt
        connection.execute(
            """
            INSERT INTO m4_hearing_checkpoints(
                run_id, checkpoint_id, checkpoint_sha256,
                hearing_id, hearing_sha256,
                cycle_scope_id, cycle_scope_sha256, case_id,
                version, phase, judge_cycle,
                prior_acquisition_rounds, prior_rework_rounds,
                cycle_pack_id, cycle_pack_version,
                current_pack_id, current_pack_version,
                previous_checkpoint_id, previous_checkpoint_sha256, previous_phase,
                initial_trigger_review_id, initial_defect_codes_json,
                cycle_trigger_review_id, cycle_trigger_defect_codes_json,
                retrieval_receipt_id, retrieval_receipt_sha256,
                prosecutor_output_id, defender_output_id, judge_output_id,
                acquisition_request_id, tool_receipt_id, procedural_review_id,
                human_review_receipt_id, human_review_receipt_sha256,
                human_review_reason,
                model_request_refs_json, model_response_refs_json,
                parse_receipt_refs_json, usage_receipt_ids_json,
                failure_authority_ids_json, manifest_id, checkpoint_json
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            (
                checkpoint.run_id,
                checkpoint.checkpoint_id,
                checkpoint.checkpoint_sha256,
                checkpoint.hearing_session_id,
                checkpoint.hearing_session_sha256,
                checkpoint.cycle_scope_id,
                checkpoint.cycle_scope_sha256,
                checkpoint.case_id,
                checkpoint.version,
                checkpoint.phase.value,
                checkpoint.judge_cycle,
                checkpoint.prior_acquisition_rounds,
                checkpoint.prior_rework_rounds,
                checkpoint.cycle_evidence_pack_id,
                checkpoint.cycle_evidence_pack_version,
                checkpoint.current_evidence_pack_id,
                checkpoint.current_evidence_pack_version,
                checkpoint.previous_checkpoint_id,
                checkpoint.previous_checkpoint_sha256,
                checkpoint.previous_phase.value if checkpoint.previous_phase is not None else None,
                (
                    checkpoint.initial_trigger_review_ref.artifact_id
                    if checkpoint.initial_trigger_review_ref is not None
                    else None
                ),
                canonical_json([code.value for code in checkpoint.initial_defect_codes]),
                (
                    checkpoint.cycle_trigger_review_ref.artifact_id
                    if checkpoint.cycle_trigger_review_ref is not None
                    else None
                ),
                canonical_json([code.value for code in checkpoint.cycle_trigger_defect_codes]),
                retrieval.receipt_id if retrieval is not None else None,
                retrieval.receipt_sha256 if retrieval is not None else None,
                (
                    checkpoint.prosecutor_output.output_id
                    if checkpoint.prosecutor_output is not None
                    else None
                ),
                (
                    checkpoint.defender_output.output_id
                    if checkpoint.defender_output is not None
                    else None
                ),
                (
                    checkpoint.judge_output.output_id
                    if checkpoint.judge_output is not None
                    else None
                ),
                (
                    checkpoint.acquisition_request.request_id
                    if checkpoint.acquisition_request is not None
                    else None
                ),
                (
                    checkpoint.tool_execution_receipt.receipt_id
                    if checkpoint.tool_execution_receipt is not None
                    else None
                ),
                (
                    checkpoint.procedural_review_ref.artifact_id
                    if checkpoint.procedural_review_ref is not None
                    else None
                ),
                checkpoint.human_review_receipt_id,
                checkpoint.human_review_receipt_sha256,
                checkpoint.human_review_reason.value
                if checkpoint.human_review_reason is not None
                else None,
                canonical_json(
                    [ref.model_dump(mode="json") for ref in checkpoint.model_request_refs]
                ),
                canonical_json(
                    [ref.model_dump(mode="json") for ref in checkpoint.model_response_refs]
                ),
                canonical_json(
                    [ref.model_dump(mode="json") for ref in checkpoint.parse_receipt_refs]
                ),
                canonical_json([item.usage_receipt_id for item in checkpoint.usage_receipts]),
                canonical_json([item.authority_id for item in checkpoint.failure_authorities]),
                checkpoint.manifest_id,
                _contract_document(checkpoint),
            ),
        )

    def _insert_precedent_retrieval(
        self,
        connection: sqlite3.Connection,
        receipt: HearingPrecedentRetrievalReceipt,
        document: str,
    ) -> None:
        connection.execute(
            """
            INSERT INTO m4_precedent_retrieval_receipts(
                run_id, retrieval_receipt_id, hearing_id,
                cycle_scope_id, cycle_scope_sha256, case_id,
                prior_acquisition_rounds, prior_rework_rounds,
                current_pack_id, current_pack_version,
                evidence_class, violation_type, rule_version, top_k,
                initial_trigger_review_id, initial_defect_codes_json,
                rework_review_id, rework_defect_codes_json,
                candidate_precedent_refs_json, candidate_snapshot_sha256,
                visible_precedent_refs_json, visible_snapshot_sha256,
                scored_precedents_json, retrieval_status, degraded_reason,
                precedent_retrieval_degraded, retriever_version,
                retriever_manifest_id, query_sha256,
                embedding_model_manifest_id, manifest_id,
                receipt_json, document_sha256
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            (
                receipt.run_id,
                receipt.receipt_id,
                receipt.hearing_session_id,
                receipt.cycle_scope_id,
                receipt.cycle_scope_sha256,
                receipt.case_id,
                receipt.prior_acquisition_rounds,
                receipt.prior_rework_rounds,
                receipt.current_evidence_pack_id,
                receipt.current_evidence_pack_version,
                receipt.evidence_class.value,
                receipt.violation_type.value,
                receipt.rule_version,
                receipt.top_k,
                (
                    receipt.initial_trigger_review_ref.artifact_id
                    if receipt.initial_trigger_review_ref is not None
                    else None
                ),
                canonical_json([code.value for code in receipt.initial_defect_codes]),
                (
                    receipt.rework_review_ref.artifact_id
                    if receipt.rework_review_ref is not None
                    else None
                ),
                canonical_json([code.value for code in receipt.rework_defect_codes]),
                canonical_json(
                    [ref.model_dump(mode="json") for ref in receipt.candidate_precedent_refs]
                ),
                receipt.candidate_snapshot_sha256,
                canonical_json(
                    [ref.model_dump(mode="json") for ref in receipt.visible_precedent_refs]
                ),
                receipt.visible_snapshot_sha256,
                canonical_json(
                    [item.model_dump(mode="json") for item in receipt.scored_precedents]
                ),
                receipt.status.value,
                receipt.degraded_reason.value if receipt.degraded_reason is not None else None,
                int(receipt.status.value == "DEGRADED"),
                receipt.retriever_version,
                receipt.retriever_manifest_id,
                receipt.query_sha256,
                receipt.embedding_model_manifest_id,
                receipt.manifest_id,
                document,
                receipt.receipt_sha256,
            ),
        )

    def _validate_complete_hearing_record(
        self,
        connection: sqlite3.Connection,
        hearing_round: HearingRound,
    ) -> HearingRecord:
        return self._rebuild_hearing_record(
            connection,
            run_id=hearing_round.run_id,
            case_id=hearing_round.case_id,
            hearing_id=hearing_round.hearing_session_id,
            appended_round=hearing_round,
        )

    def _rebuild_hearing_record(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        case_id: str,
        hearing_id: str,
        appended_round: HearingRound | None = None,
    ) -> HearingRecord:
        session = self._load_hearing_session(
            connection,
            run_id,
            hearing_id,
        )
        if session.case_id != case_id:
            raise ContractViolation("hearing record belongs to another Case")
        rows = connection.execute(
            """
            SELECT round_id
            FROM m4_hearing_rounds
            WHERE run_id = ? AND hearing_id = ?
            ORDER BY round_index
            """,
            (run_id, hearing_id),
        ).fetchall()
        persisted_rounds = tuple(
            self._load_hearing_round(
                connection,
                run_id,
                _row_str(row, "round_id"),
            )
            for row in rows
        )
        rounds = (
            (*persisted_rounds, appended_round) if appended_round is not None else persisted_rounds
        )
        if not rounds:
            raise ContractViolation("hearing record requires at least one complete round")
        if tuple(item.round_index for item in rounds) != tuple(range(1, len(rounds) + 1)):
            raise ContractViolation("hearing round append is out of sequence")
        hearing_round = rounds[-1]

        usage_rows = connection.execute(
            """
            SELECT usage_json, document_sha256
            FROM m4_hearing_usage_receipts
            WHERE run_id = ? AND hearing_id = ?
            ORDER BY cycle_scope_id, role, request_id
            """,
            (run_id, hearing_id),
        ).fetchall()
        usage: list[HearingUsageReceipt] = []
        for row in usage_rows:
            raw = _row_str(row, "usage_json")
            try:
                receipt = HearingUsageReceipt.model_validate_json(raw)
            except ValidationError as exc:
                raise RepositoryIntegrityError("stored hearing usage receipt is invalid") from exc
            _verify_document(raw, _row_str(row, "document_sha256"), receipt)
            usage.append(receipt)
        usage_receipts = tuple(
            sorted(
                usage,
                key=lambda item: (
                    item.round_index,
                    item.role.value,
                    item.request_ref.artifact_id,
                ),
            )
        )

        failure_rows = connection.execute(
            """
            SELECT authority_json, document_sha256
            FROM m4_model_call_failure_authorities
            WHERE run_id = ? AND hearing_id = ?
            ORDER BY cycle_scope_id, role, request_id, authority_id
            """,
            (run_id, hearing_id),
        ).fetchall()
        failures: list[HearingModelCallFailureAuthority] = []
        for row in failure_rows:
            raw = _row_str(row, "authority_json")
            try:
                authority = HearingModelCallFailureAuthority.model_validate_json(raw)
            except ValidationError as exc:
                raise RepositoryIntegrityError(
                    "stored hearing failure authority is invalid"
                ) from exc
            _verify_document(raw, _row_str(row, "document_sha256"), authority)
            failures.append(authority)
        failure_authorities = tuple(
            sorted(
                failures,
                key=lambda item: (
                    item.request.round_index,
                    item.role.value,
                    item.request.request_id,
                    item.authority_id,
                ),
            )
        )
        # A successful role output names only the final call.  A malformed
        # primary followed by a valid repair has two charged provider calls,
        # and strict-failure generations can add still more.  Usage is the
        # exactly-once provider-call root, so rebuild the record trace from all
        # completed claims and require one matching parse receipt for each.
        usage_request_ids = {item.request_ref.artifact_id for item in usage_receipts}
        usage_response_ids = {item.response_ref.artifact_id for item in usage_receipts}
        completed_claim_rows = connection.execute(
            """
            SELECT request_id, response_id
            FROM m4_model_call_claims
            WHERE run_id = ? AND hearing_id = ? AND status = 'COMPLETED'
            ORDER BY request_id
            """,
            (run_id, hearing_id),
        ).fetchall()
        completed_claims = {
            _row_str(row, "request_id"): _row_str(row, "response_id")
            for row in completed_claim_rows
        }
        if (
            len(completed_claims) != len(completed_claim_rows)
            or set(completed_claims) != usage_request_ids
            or set(completed_claims.values()) != usage_response_ids
            or any(
                completed_claims.get(item.request_ref.artifact_id) != item.response_ref.artifact_id
                for item in usage_receipts
            )
        ):
            raise RepositoryIntegrityError(
                "hearing record usage does not exactly cover completed call claims"
            )
        parse_rows = connection.execute(
            """
            SELECT request_id, response_id, parse_receipt_id
            FROM m4_model_parse_receipts
            WHERE run_id = ? AND hearing_id = ?
            ORDER BY request_id
            """,
            (run_id, hearing_id),
        ).fetchall()
        parse_by_request = {
            _row_str(row, "request_id"): (
                _row_str(row, "response_id"),
                _row_str(row, "parse_receipt_id"),
            )
            for row in parse_rows
        }
        if (
            len(parse_by_request) != len(parse_rows)
            or set(parse_by_request) != usage_request_ids
            or any(
                parse_by_request[request_id][0] != response_id
                for request_id, response_id in completed_claims.items()
            )
        ):
            raise RepositoryIntegrityError(
                "hearing record parse history does not exactly cover provider calls"
            )
        request_refs = tuple(
            sorted(
                (item.request_ref for item in usage_receipts),
                key=lambda ref: ref.sort_key,
            )
        )
        response_refs = tuple(
            sorted(
                (item.response_ref for item in usage_receipts),
                key=lambda ref: ref.sort_key,
            )
        )
        parse_refs = tuple(
            sorted(
                (
                    ArtifactRef(
                        kind=ArtifactKind.MODEL_PARSE_RECEIPT,
                        artifact_id=parse_receipt_id,
                    )
                    for _, parse_receipt_id in parse_by_request.values()
                ),
                key=lambda ref: ref.sort_key,
            )
        )
        loaded_case = self._host._load_case(connection, hearing_round.run_id, hearing_round.case_id)
        if (
            not loaded_case.snapshot.case.evidence_packs
            or loaded_case.snapshot.case.evidence_packs[-1].pack_id
            != hearing_round.resulting_evidence_pack_id
            or loaded_case.snapshot.case.evidence_packs[-1].version
            != hearing_round.resulting_evidence_pack_version
        ):
            raise ConcurrentModification(
                "hearing round does not close the case's latest evidence pack"
            )
        try:
            return HearingRecord(
                run_id=hearing_round.run_id,
                case_id=hearing_round.case_id,
                version=len(rounds),
                session=session,
                screening_id=session.screening_id,
                initial_evidence_pack_id=session.initial_evidence_pack_id,
                initial_evidence_pack_version=session.initial_evidence_pack_version,
                acquisition_round_limit=session.acquisition_round_limit,
                rework_round_limit=session.rework_round_limit,
                rounds=rounds,
                model_request_refs=request_refs,
                model_response_refs=response_refs,
                parse_receipt_refs=parse_refs,
                usage_receipts=usage_receipts,
                failure_authorities=failure_authorities,
                manifest_id=session.manifest_id,
            )
        except ValidationError as exc:
            raise ContractViolation("hearing round does not close a complete typed record") from exc

    def _insert_hearing_round(
        self,
        connection: sqlite3.Connection,
        hearing_round: HearingRound,
    ) -> None:
        retrieval = hearing_round.precedent_retrieval_receipt
        connection.execute(
            """
            INSERT INTO m4_hearing_rounds(
                run_id, round_id, hearing_id,
                cycle_scope_id, cycle_scope_sha256, case_id,
                round_index, prior_acquisition_rounds, prior_rework_rounds,
                current_pack_id, current_pack_version,
                precedent_retrieval_degraded,
                retrieval_receipt_id, retrieval_receipt_sha256,
                initial_trigger_review_id, initial_defect_codes_json,
                rework_review_id, rework_defect_codes_json,
                prosecutor_output_id, defender_output_id, judge_output_id,
                acquisition_request_id, tool_receipt_id,
                resulting_pack_id, resulting_pack_version,
                manifest_id, round_json
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?
            )
            """,
            (
                hearing_round.run_id,
                hearing_round.round_id,
                hearing_round.hearing_session_id,
                hearing_round.cycle_scope_id,
                hearing_round.cycle_scope_sha256,
                hearing_round.case_id,
                hearing_round.round_index,
                hearing_round.prior_acquisition_rounds,
                hearing_round.prior_rework_rounds,
                hearing_round.current_evidence_pack_id,
                hearing_round.current_evidence_pack_version,
                int(hearing_round.precedent_retrieval_degraded),
                retrieval.receipt_id,
                retrieval.receipt_sha256,
                (
                    hearing_round.initial_trigger_review_ref.artifact_id
                    if hearing_round.initial_trigger_review_ref is not None
                    else None
                ),
                canonical_json([code.value for code in hearing_round.initial_defect_codes]),
                (
                    hearing_round.rework_review_ref.artifact_id
                    if hearing_round.rework_review_ref is not None
                    else None
                ),
                canonical_json([code.value for code in hearing_round.rework_defect_codes]),
                hearing_round.prosecutor_output.output_id,
                hearing_round.defender_output.output_id,
                hearing_round.judge_output.output_id,
                (
                    hearing_round.acquisition_request.request_id
                    if hearing_round.acquisition_request is not None
                    else None
                ),
                (
                    hearing_round.tool_execution_receipt.receipt_id
                    if hearing_round.tool_execution_receipt is not None
                    else None
                ),
                hearing_round.resulting_evidence_pack_id,
                hearing_round.resulting_evidence_pack_version,
                hearing_round.manifest_id,
                _contract_document(hearing_round),
            ),
        )

    def _load_hearing_session(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        hearing_id: str,
    ) -> HearingSession:
        row = connection.execute(
            "SELECT * FROM m4_hearings WHERE run_id = ? AND hearing_id = ?",
            (run_id, hearing_id),
        ).fetchone()
        if row is None:
            raise EvidenceMissing(f"hearing session is absent from run {run_id}")
        raw = _row_str(row, "hearing_json")
        try:
            session = HearingSession.model_validate_json(raw)
        except ValidationError as exc:
            raise RepositoryIntegrityError("stored hearing session is invalid") from exc
        _verify_contract_document(raw, session)
        if (
            session.run_id != run_id
            or session.session_id != hearing_id
            or session.session_sha256 != _row_str(row, "document_sha256")
            or session.case_id != _row_str(row, "case_id")
            or session.screening_id != _row_str(row, "screening_id")
            or session.entry_status.value != _row_str(row, "entry_status")
            or session.initial_evidence_pack_id != _row_str(row, "initial_pack_id")
            or session.initial_evidence_pack_version != _row_int(row, "initial_pack_version")
            or session.manifest_id != _row_str(row, "manifest_id")
        ):
            raise RepositoryIntegrityError("hearing session indexes conflict with its document")
        return session

    def _load_hearing_cycle(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        cycle_id: str,
    ) -> HearingCycleScope:
        row = connection.execute(
            "SELECT * FROM m4_hearing_cycles WHERE run_id = ? AND cycle_id = ?",
            (run_id, cycle_id),
        ).fetchone()
        if row is None:
            raise EvidenceMissing(f"hearing cycle is absent from run {run_id}")
        raw = _row_str(row, "cycle_json")
        try:
            cycle = HearingCycleScope.model_validate_json(raw)
        except ValidationError as exc:
            raise RepositoryIntegrityError("stored hearing cycle is invalid") from exc
        _verify_contract_document(raw, cycle)
        if (
            cycle.run_id != run_id
            or cycle.cycle_id != cycle_id
            or cycle.cycle_sha256 != _row_str(row, "cycle_sha256")
            or cycle.hearing_session_id != _row_str(row, "hearing_id")
            or cycle.case_id != _row_str(row, "case_id")
            or cycle.cycle_index != _row_int(row, "cycle_index")
            or cycle.prior_acquisition_rounds != _row_int(row, "prior_acquisition_rounds")
            or cycle.prior_rework_rounds != _row_int(row, "prior_rework_rounds")
            or cycle.cycle_evidence_pack_id != _row_str(row, "cycle_pack_id")
            or cycle.cycle_evidence_pack_version != _row_int(row, "cycle_pack_version")
            or cycle.manifest_id != _row_str(row, "manifest_id")
        ):
            raise RepositoryIntegrityError("hearing cycle indexes conflict with its document")
        return cycle

    def _load_precedent_retrieval(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        receipt_id: str,
    ) -> HearingPrecedentRetrievalReceipt:
        row = connection.execute(
            """
            SELECT * FROM m4_precedent_retrieval_receipts
            WHERE run_id = ? AND retrieval_receipt_id = ?
            """,
            (run_id, receipt_id),
        ).fetchone()
        if row is None:
            raise EvidenceMissing(f"precedent retrieval is absent from run {run_id}")
        raw = _row_str(row, "receipt_json")
        try:
            receipt = HearingPrecedentRetrievalReceipt.model_validate_json(raw)
        except ValidationError as exc:
            raise RepositoryIntegrityError("stored precedent retrieval is invalid") from exc
        _verify_contract_document(raw, receipt)
        if (
            receipt.run_id != run_id
            or receipt.receipt_id != receipt_id
            or receipt.receipt_sha256 != _row_str(row, "document_sha256")
            or receipt.hearing_session_id != _row_str(row, "hearing_id")
            or receipt.cycle_scope_id != _row_str(row, "cycle_scope_id")
            or receipt.cycle_scope_sha256 != _row_str(row, "cycle_scope_sha256")
            or receipt.case_id != _row_str(row, "case_id")
            or receipt.round_index
            != 1 + _row_int(row, "prior_acquisition_rounds") + _row_int(row, "prior_rework_rounds")
            or receipt.current_evidence_pack_id != _row_str(row, "current_pack_id")
            or receipt.current_evidence_pack_version != _row_int(row, "current_pack_version")
            or receipt.status.value != _row_str(row, "retrieval_status")
            or receipt.manifest_id != _row_str(row, "manifest_id")
        ):
            raise RepositoryIntegrityError("precedent retrieval indexes conflict with its document")
        return receipt

    def _load_hearing_checkpoint(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        checkpoint_id: str,
    ) -> HearingCheckpoint:
        row = connection.execute(
            "SELECT * FROM m4_hearing_checkpoints WHERE run_id = ? AND checkpoint_id = ?",
            (run_id, checkpoint_id),
        ).fetchone()
        if row is None:
            raise EvidenceMissing(f"hearing checkpoint is absent from run {run_id}")
        raw = _row_str(row, "checkpoint_json")
        try:
            checkpoint = HearingCheckpoint.model_validate_json(raw)
        except ValidationError as exc:
            raise RepositoryIntegrityError("stored hearing checkpoint is invalid") from exc
        _verify_contract_document(raw, checkpoint)
        if (
            checkpoint.run_id != run_id
            or checkpoint.checkpoint_id != checkpoint_id
            or checkpoint.checkpoint_sha256 != _row_str(row, "checkpoint_sha256")
            or checkpoint.hearing_session_id != _row_str(row, "hearing_id")
            or checkpoint.hearing_session_sha256 != _row_str(row, "hearing_sha256")
            or checkpoint.cycle_scope_id != _row_str(row, "cycle_scope_id")
            or checkpoint.cycle_scope_sha256 != _row_str(row, "cycle_scope_sha256")
            or checkpoint.case_id != _row_str(row, "case_id")
            or checkpoint.version != _row_int(row, "version")
            or checkpoint.phase.value != _row_str(row, "phase")
            or checkpoint.current_evidence_pack_id != _row_str(row, "current_pack_id")
            or checkpoint.current_evidence_pack_version
            != _row_int(
                row,
                "current_pack_version",
            )
            or checkpoint.manifest_id != _row_str(row, "manifest_id")
        ):
            raise RepositoryIntegrityError("hearing checkpoint indexes conflict with its document")
        return checkpoint

    def _load_hearing_round(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        round_id: str,
    ) -> HearingRound:
        row = connection.execute(
            "SELECT * FROM m4_hearing_rounds WHERE run_id = ? AND round_id = ?",
            (run_id, round_id),
        ).fetchone()
        if row is None:
            raise EvidenceMissing(f"hearing round is absent from run {run_id}")
        raw = _row_str(row, "round_json")
        try:
            hearing_round = HearingRound.model_validate_json(raw)
        except ValidationError as exc:
            raise RepositoryIntegrityError("stored hearing round is invalid") from exc
        _verify_contract_document(raw, hearing_round)
        if (
            hearing_round.run_id != run_id
            or hearing_round.round_id != round_id
            or hearing_round.hearing_session_id != _row_str(row, "hearing_id")
            or hearing_round.cycle_scope_id != _row_str(row, "cycle_scope_id")
            or hearing_round.cycle_scope_sha256 != _row_str(row, "cycle_scope_sha256")
            or hearing_round.case_id != _row_str(row, "case_id")
            or hearing_round.round_index != _row_int(row, "round_index")
            or hearing_round.current_evidence_pack_id != _row_str(row, "current_pack_id")
            or hearing_round.current_evidence_pack_version
            != _row_int(
                row,
                "current_pack_version",
            )
            or hearing_round.manifest_id != _row_str(row, "manifest_id")
        ):
            raise RepositoryIntegrityError("hearing round indexes conflict with its document")
        return hearing_round


__all__ = ["SQLiteHearingRepository"]
