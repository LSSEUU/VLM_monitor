"""Static host surface shared by behavior-only M3 repository mixins."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from labcourt.contracts.audit import AuditEntry
from labcourt.contracts.backlog import (
    BacklogCompletionReceipt,
    BacklogItem,
    BacklogLeaseIdentity,
    BacklogRetryContext,
    BacklogRetryFailure,
    BacklogRetrySuccess,
    BacklogStrictParseFailureProof,
)
from labcourt.contracts.cases import Case, TimelineEntry, UsageSummary
from labcourt.contracts.enums import (
    ArtifactKind,
    BacklogReasonCode,
    BacklogStage,
    CaseStatus,
)
from labcourt.contracts.evidence import EvidencePack
from labcourt.contracts.model_call_failures import (
    ModelCallFailureAuthority,
    ModelCallFailureClosureKind,
)
from labcourt.contracts.screening import (
    CachedModelResponse,
    ModelParseReceipt,
    ParsedScreeningOutput,
    ScreeningResult,
    VLMCallRequest,
    VLMResponse,
)
from labcourt.contracts.storage import ArtifactRef, ClosureReport
from labcourt.contracts.verdicts import ProceduralDefect, ProceduralReview, Verdict
from labcourt.ports.evidence_repository import AuditHead, CaseSnapshot
from labcourt.ports.m3_semantics import M3SemanticVerifier
from labcourt.ports.model_response_recovery import (
    ModelCallRecoveryCandidate,
    ModelCallRecoveryScan,
    ModelCallRecoveryScanFailureCode,
)
from labcourt.ports.procedural_review import ProceduralReviewVerifier
from labcourt.ports.screening_repository import (
    M3BacklogRetryCommit,
    M3CaseCommit,
    ModelCallClaim,
    ModelCallFailureIntent,
)
from labcourt.ports.vlm import (
    RawModelResponseVerifier,
)

from ._sqlite_read_session import SQLiteReadSession
from .sqlite_m3_repository_support import CurrentPackVerifier

if TYPE_CHECKING:

    class SQLiteM3RepositoryHost(Protocol):
        _database_path: Path
        _busy_timeout_ms: int
        _clock: Callable[[], datetime] | None
        _current_pack_verifier: CurrentPackVerifier | None
        _raw_response_verifier: RawModelResponseVerifier | None
        _procedural_review_verifier: ProceduralReviewVerifier | None
        _semantic_verifier: M3SemanticVerifier | None
        _artifact_recovery_fence_connection: ContextVar[sqlite3.Connection | None]

        def __init__(
            self,
            database_path: str | Path,
            busy_timeout_ms: int,
            clock: object | None = None,
            *,
            current_pack_verifier: CurrentPackVerifier | None = None,
            raw_response_verifier: RawModelResponseVerifier | None = None,
            procedural_review_verifier: ProceduralReviewVerifier | None = None,
            semantic_verifier: M3SemanticVerifier | None = None,
        ) -> None: ...

        @contextmanager
        def _immediate(self) -> Iterator[sqlite3.Connection]: ...

        @contextmanager
        def _read(self) -> Iterator[sqlite3.Connection]: ...

        def _connection(self) -> sqlite3.Connection: ...

        @contextmanager
        def model_response_artifact_recovery_fence(
            self,
            run_id: str,
        ) -> Iterator[None]: ...

        def append_raw_response(self, response: VLMResponse) -> VLMResponse: ...

        def load_raw_response(self, run_id: str, response_id: str) -> VLMResponse: ...

        def load_raw_response_for_request(
            self,
            run_id: str,
            request_id: str,
        ) -> VLMResponse | None: ...

        def model_response_is_referenced(
            self,
            run_id: str,
            response_id: str,
            content_sha256: str,
        ) -> bool: ...

        def claim_model_call(
            self,
            run_id: str,
            request: VLMCallRequest,
            owner_token: str,
            backlog_lease: BacklogLeaseIdentity | None = None,
        ) -> ModelCallClaim: ...

        def _known_failure_authorizes_retry(
            self,
            connection: sqlite3.Connection,
            *,
            row: sqlite3.Row,
            request: VLMCallRequest,
            backlog_lease: BacklogLeaseIdentity | None,
        ) -> bool: ...

        def scan_model_call_recovery_candidates(
            self,
            run_id: str,
            max_items: int,
        ) -> ModelCallRecoveryScan: ...

        def complete_expired_model_call_from_recovery(
            self,
            run_id: str,
            request: VLMCallRequest,
            response: VLMResponse,
            observed_lease_expires_at: datetime,
            observed_takeover_count: int,
        ) -> CachedModelResponse: ...

        def complete_model_call(
            self,
            run_id: str,
            request: VLMCallRequest,
            response: VLMResponse,
            owner_token: str,
        ) -> CachedModelResponse: ...

        def append_parse_receipt(
            self,
            receipt: ModelParseReceipt,
            parsed_output: ParsedScreeningOutput | None = None,
        ) -> ModelParseReceipt: ...

        def load_parse_receipt(self, run_id: str, parse_receipt_id: str) -> ModelParseReceipt: ...

        def load_parse_receipt_for_output(
            self,
            run_id: str,
            parsed_output_id: str,
        ) -> ModelParseReceipt: ...

        def load_parse_history_for_output(
            self,
            run_id: str,
            parsed_output_id: str,
        ) -> tuple[ModelParseReceipt, ...]: ...

        def load_parsed_output(
            self, run_id: str, parsed_output_id: str
        ) -> ParsedScreeningOutput: ...

        def get(
            self,
            run_id: str,
            request: VLMCallRequest,
        ) -> CachedModelResponse | None: ...

        def put(
            self,
            run_id: str,
            request: VLMCallRequest,
            response: VLMResponse,
        ) -> CachedModelResponse: ...

        def commit_screening(
            self,
            run_id: str,
            expected_revision: int,
            expected_audit_head: AuditHead,
            current_pack_closure: ClosureReport,
            screening: ScreeningResult,
        ) -> M3CaseCommit: ...

        def commit_backlog_screening_success(
            self,
            run_id: str,
            expected_revision: int,
            expected_audit_head: AuditHead,
            current_pack_closure: ClosureReport,
            success: BacklogRetrySuccess,
            screening: ScreeningResult,
        ) -> M3BacklogRetryCommit: ...

        def commit_verdict_review(
            self,
            run_id: str,
            expected_revision: int,
            expected_audit_head: AuditHead,
            current_pack_closure: ClosureReport,
            verdict: Verdict,
            review: ProceduralReview,
        ) -> M3CaseCommit: ...

        def commit_backlog_verdict_review_success(
            self,
            run_id: str,
            expected_revision: int,
            expected_audit_head: AuditHead,
            current_pack_closure: ClosureReport,
            success: BacklogRetrySuccess,
            verdict: Verdict,
            review: ProceduralReview,
            screening: ScreeningResult | None = None,
        ) -> M3BacklogRetryCommit: ...

        def commit_backlog_retry_failure(
            self,
            run_id: str,
            expected_revision: int,
            expected_audit_head: AuditHead,
            current_pack_closure: ClosureReport,
            failure: BacklogRetryFailure,
            model_call_failure: ModelCallFailureIntent | None = None,
        ) -> M3BacklogRetryCommit: ...

        def load_case(self, run_id: str, case_id: str) -> CaseSnapshot: ...

        def select_case_ids_bounded(
            self,
            run_id: str,
            limit: int,
        ) -> tuple[tuple[str, ...], int]: ...

        def load_screening(self, run_id: str, screening_id: str) -> ScreeningResult: ...

        def load_verdict(self, run_id: str, verdict_id: str) -> Verdict: ...

        def load_procedural_review(self, run_id: str, review_id: str) -> ProceduralReview: ...

        def enqueue(self, run_id: str, item: BacklogItem) -> BacklogItem: ...

        def commit_backlog(
            self,
            run_id: str,
            expected_revision: int,
            expected_audit_head: AuditHead,
            current_pack_closure: ClosureReport,
            item: BacklogItem,
            response_ids: tuple[str, ...] = (),
            model_call_failure: ModelCallFailureIntent | None = None,
        ) -> M3CaseCommit: ...

        def lease_next(
            self,
            run_id: str,
            stage: BacklogStage,
            lease_owner_sha256: str,
            lease_expires_at: datetime,
        ) -> BacklogItem | None: ...

        def complete(
            self,
            run_id: str,
            item_id: str,
            expected_lease_id: str,
        ) -> BacklogItem: ...

        def release(
            self,
            run_id: str,
            item_id: str,
            expected_lease_id: str,
        ) -> BacklogItem: ...

        def reclaim_expired(
            self,
            run_id: str,
            not_after: datetime,
            limit: int,
        ) -> tuple[BacklogItem, ...]: ...

        def load_backlog_item(self, run_id: str, item_id: str) -> BacklogItem: ...

        def _commit_expired_backlog_lease(
            self,
            connection: sqlite3.Connection,
            *,
            current: BacklogItem,
            cutoff: datetime,
        ) -> M3BacklogRetryCommit: ...

        def _model_call_recovery_candidate_from_row(
            self,
            row: sqlite3.Row,
        ) -> ModelCallRecoveryCandidate | ModelCallRecoveryScanFailureCode: ...

        def _claim_from_row(
            self,
            row: sqlite3.Row,
            request: VLMCallRequest,
        ) -> ModelCallClaim: ...

        def _append_raw_response_in_transaction(
            self,
            connection: sqlite3.Connection,
            response: VLMResponse,
        ) -> VLMResponse: ...

        def _put_in_transaction(
            self,
            connection: sqlite3.Connection,
            run_id: str,
            request: VLMCallRequest,
            response: VLMResponse,
        ) -> CachedModelResponse: ...

        def _load_response(
            self,
            connection: sqlite3.Connection,
            run_id: str,
            response_id: str,
        ) -> VLMResponse: ...

        @staticmethod
        def _has_durable_model_response_reference(
            connection: sqlite3.Connection,
            run_id: str,
            response_id: str,
        ) -> bool: ...

        def _response_from_row(self, row: sqlite3.Row) -> VLMResponse: ...

        @staticmethod
        def _validate_parse_binding(
            receipt: ModelParseReceipt,
            output: ParsedScreeningOutput | None,
        ) -> None: ...

        @staticmethod
        def _require_receipt_response_binding(
            receipt: ModelParseReceipt,
            response: VLMResponse,
        ) -> None: ...

        def _insert_parsed_output(
            self,
            connection: sqlite3.Connection,
            output: ParsedScreeningOutput,
        ) -> None: ...

        def _load_parsed_output(
            self,
            connection: sqlite3.Connection,
            run_id: str,
            parsed_output_id: str,
        ) -> ParsedScreeningOutput: ...

        @staticmethod
        def _parsed_output_from_row(row: sqlite3.Row) -> ParsedScreeningOutput: ...

        def _parse_receipt_from_row(
            self,
            connection: sqlite3.Connection,
            row: sqlite3.Row,
        ) -> ModelParseReceipt: ...

        def _load_parse_history_for_output(
            self,
            connection: sqlite3.Connection,
            run_id: str,
            parsed_output_id: str,
        ) -> tuple[ModelParseReceipt, ...]: ...

        @staticmethod
        def _validate_request_response_binding(
            run_id: str,
            request: VLMCallRequest,
            response: VLMResponse,
        ) -> None: ...

        def _cached_response_from_row(
            self,
            connection: sqlite3.Connection,
            row: sqlite3.Row,
            request: VLMCallRequest,
        ) -> CachedModelResponse: ...

        def _request_from_cache_row(self, row: sqlite3.Row) -> VLMCallRequest: ...

        def _request_for_response(
            self,
            connection: sqlite3.Connection,
            response: VLMResponse,
        ) -> VLMCallRequest: ...

        def _reverify_raw_response(
            self,
            *,
            run_id: str,
            request: VLMCallRequest,
            response: VLMResponse,
        ) -> None: ...

        def _reverify_parse_history_raw(
            self,
            connection: sqlite3.Connection,
            *,
            run_id: str,
            parse_history: tuple[ModelParseReceipt, ...],
        ) -> None: ...

        def _reverify_backlog_responses(
            self,
            connection: sqlite3.Connection,
            *,
            run_id: str,
            response_ids: tuple[str, ...],
            reason_code: BacklogReasonCode,
        ) -> None: ...

        def _strict_failure_history(
            self,
            connection: sqlite3.Connection,
            *,
            item: BacklogItem,
            response_ids: tuple[str, ...],
            expected_context: BacklogRetryContext | None,
        ) -> tuple[tuple[ModelParseReceipt, VLMCallRequest, VLMResponse], ...]: ...

        def _require_strict_parse_failure_proof(
            self,
            connection: sqlite3.Connection,
            *,
            item: BacklogItem,
            proof: BacklogStrictParseFailureProof,
        ) -> None: ...

        def _new_backlog_usage_response_ids(
            self,
            connection: sqlite3.Connection,
            *,
            snapshot: CaseSnapshot,
            response_ids: tuple[str, ...],
            backlog_item_id: str | None = None,
        ) -> tuple[str, ...]: ...

        def _usage_delta_for_output(
            self,
            connection: sqlite3.Connection,
            run_id: str,
            parsed_output_id: str,
        ) -> UsageSummary: ...

        def _consume_model_call_usage(
            self,
            connection: sqlite3.Connection,
            *,
            run_id: str,
            case_id: str,
            response_ids: tuple[str, ...],
            case_revision: int,
            consumer_kind: ArtifactKind,
            consumer_id: str,
        ) -> UsageSummary: ...

        @staticmethod
        def _add_usage(current: UsageSummary, delta: UsageSummary) -> UsageSummary: ...

        def _insert_screening_root(
            self,
            connection: sqlite3.Connection,
            screening: ScreeningResult,
            *,
            audit_sequence: int,
        ) -> None: ...

        def _insert_verdict_review_roots(
            self,
            connection: sqlite3.Connection,
            verdict: Verdict,
            review: ProceduralReview,
            *,
            audit_sequence: int,
        ) -> None: ...

        def _insert_defects(
            self,
            connection: sqlite3.Connection,
            *,
            run_id: str,
            owner_kind: ArtifactKind,
            owner_id: str,
            defects: tuple[ProceduralDefect, ...],
        ) -> None: ...

        def _verify_defect_rows(
            self,
            connection: sqlite3.Connection,
            *,
            run_id: str,
            owner_kind: ArtifactKind,
            owner_id: str,
            expected: tuple[ProceduralDefect, ...],
        ) -> None: ...

        def _find_screening_collision(
            self,
            connection: sqlite3.Connection,
            screening: ScreeningResult,
        ) -> ScreeningResult | None: ...

        def _load_screening(
            self,
            connection: sqlite3.Connection,
            run_id: str,
            screening_id: str,
        ) -> ScreeningResult: ...

        def _screening_from_row(
            self,
            connection: sqlite3.Connection,
            row: sqlite3.Row,
        ) -> ScreeningResult: ...

        def _find_verdict_collision(
            self,
            connection: sqlite3.Connection,
            verdict: Verdict,
        ) -> Verdict | None: ...

        def _load_verdict(
            self,
            connection: sqlite3.Connection,
            run_id: str,
            verdict_id: str,
        ) -> Verdict: ...

        def _verdict_from_row(
            self,
            connection: sqlite3.Connection,
            row: sqlite3.Row,
        ) -> Verdict: ...

        def _find_review_collision(
            self,
            connection: sqlite3.Connection,
            review: ProceduralReview,
        ) -> ProceduralReview | None: ...

        def _load_review(
            self,
            connection: sqlite3.Connection,
            run_id: str,
            review_id: str,
        ) -> ProceduralReview: ...

        def _review_from_row(
            self,
            connection: sqlite3.Connection,
            row: sqlite3.Row,
        ) -> ProceduralReview: ...

        @staticmethod
        def _require_expected_revision(expected_revision: int) -> None: ...

        def _load_case(
            self,
            connection: sqlite3.Connection,
            run_id: str,
            case_id: str,
        ) -> CaseSnapshot: ...

        def _verify_case_roots(
            self,
            connection: sqlite3.Connection,
            case: Case,
            *,
            allow_future_roots: bool = False,
        ) -> None: ...

        def _load_pack(
            self,
            connection: sqlite3.Connection,
            run_id: str,
            pack_id: str,
        ) -> EvidencePack: ...

        def _require_commit_guards(
            self,
            connection: sqlite3.Connection,
            *,
            snapshot: CaseSnapshot,
            expected_revision: int,
            expected_audit_head: AuditHead,
            current_pack_closure: ClosureReport,
            pack_id: str,
            pack_version: int,
            require_passed_closure: bool = True,
        ) -> None: ...

        def _require_current_pack_closure(
            self,
            connection: sqlite3.Connection,
            case: Case,
            pack_id: str,
            pack_version: int,
            report: ClosureReport,
            *,
            require_passed: bool,
        ) -> ClosureReport: ...

        def _reverify_current_pack(
            self,
            connection: sqlite3.Connection,
            *,
            case: Case,
            pack_id: str,
            pack_version: int,
            expected: ClosureReport,
            require_passed: bool,
        ) -> None: ...

        def _require_case_pack_scope(
            self,
            connection: sqlite3.Connection,
            *,
            run_id: str,
            case_id: str,
            pack_id: str,
            pack_version: int,
            manifest_id: str,
        ) -> None: ...

        def _require_case_manifest(
            self,
            connection: sqlite3.Connection,
            *,
            run_id: str,
            case_id: str,
            manifest_id: str,
        ) -> None: ...

        @staticmethod
        def _case_with_updates(
            case: Case,
            *,
            status: CaseStatus,
            timeline_entry: TimelineEntry,
            current_backlog_item_id: str | None = None,
            usage: UsageSummary | None = None,
            screening_results: tuple[ScreeningResult, ...] | None = None,
            verdicts: tuple[Verdict, ...] | None = None,
            procedural_reviews: tuple[ProceduralReview, ...] | None = None,
        ) -> Case: ...

        def _head(self, connection: SQLiteReadSession, run_id: str) -> AuditHead: ...

        def _validated_head(self, connection: SQLiteReadSession, run_id: str) -> AuditHead: ...

        @staticmethod
        def _require_expected_head(actual: AuditHead, expected: AuditHead) -> None: ...

        def _recorded_at(self) -> str: ...

        def _append_audit(
            self,
            connection: sqlite3.Connection,
            head: AuditHead,
            *,
            object_ref: ArtifactRef,
            before_sha256: str,
            after_sha256: str,
        ) -> AuditEntry: ...

        def _commit_case_version(
            self,
            connection: sqlite3.Connection,
            *,
            previous: CaseSnapshot,
            new_case: Case,
            expected_head: AuditHead,
            object_ref: ArtifactRef,
        ) -> CaseSnapshot: ...

        @staticmethod
        def _validate_verdict_review_binding(
            run_id: str,
            verdict: Verdict,
            review: ProceduralReview,
        ) -> None: ...

        def _enqueue_in_transaction(
            self,
            connection: sqlite3.Connection,
            item: BacklogItem,
            *,
            item_json: str,
            item_sha256: str,
        ) -> tuple[BacklogItem, bool]: ...

        def _load_backlog_optional(
            self,
            connection: sqlite3.Connection,
            run_id: str,
            item_id: str,
        ) -> BacklogItem | None: ...

        def _backlog_from_row(
            self,
            connection: sqlite3.Connection,
            row: sqlite3.Row,
        ) -> BacklogItem: ...

        @staticmethod
        def _require_same_backlog_identity(left: BacklogItem, right: BacklogItem) -> None: ...

        def _insert_backlog_version(
            self,
            connection: sqlite3.Connection,
            item: BacklogItem,
            *,
            version: int,
        ) -> None: ...

        def _advance_backlog(
            self,
            connection: sqlite3.Connection,
            current: BacklogItem,
            updated: BacklogItem,
        ) -> int: ...

        def _load_backlog_version(
            self,
            connection: sqlite3.Connection,
            run_id: str,
            item_id: str,
            version: int,
        ) -> BacklogItem: ...

        def _load_case_version(
            self,
            connection: sqlite3.Connection,
            run_id: str,
            case_id: str,
            revision: int,
        ) -> CaseSnapshot: ...

        def _backlog_completion_receipt_from_row(
            self,
            connection: sqlite3.Connection,
            row: sqlite3.Row,
        ) -> BacklogCompletionReceipt: ...

        def _insert_backlog_completion_receipt(
            self,
            connection: sqlite3.Connection,
            *,
            item: BacklogItem,
            backlog_version: int,
            receipt: BacklogCompletionReceipt,
        ) -> None: ...

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
        ) -> ModelCallFailureAuthority: ...

        def _model_call_failure_authority_from_row(
            self,
            row: sqlite3.Row,
        ) -> ModelCallFailureAuthority: ...

        def _require_model_call_failure_replay(
            self,
            connection: sqlite3.Connection,
            *,
            intent: ModelCallFailureIntent,
            item: BacklogItem,
            closure_kind: ModelCallFailureClosureKind,
            receipt: BacklogCompletionReceipt | None,
        ) -> None: ...

        def _load_backlog_retry_replay(
            self,
            connection: sqlite3.Connection,
            outcome: BacklogRetrySuccess | BacklogRetryFailure,
        ) -> M3BacklogRetryCommit | None: ...

        def _require_active_backlog_lease(
            self,
            connection: sqlite3.Connection,
            *,
            run_id: str,
            lease: BacklogLeaseIdentity,
            manifest_id: str,
        ) -> tuple[BacklogItem, CaseSnapshot]: ...

        @staticmethod
        def _parse_history_response_refs(
            parse_history: tuple[ModelParseReceipt, ...],
        ) -> tuple[ArtifactRef, ...]: ...

        def _require_retry_parse_context(
            self,
            connection: sqlite3.Connection,
            *,
            run_id: str,
            parse_history: tuple[ModelParseReceipt, ...],
            lease: BacklogLeaseIdentity,
        ) -> None: ...

        def _load_audit_entry(
            self,
            connection: sqlite3.Connection,
            run_id: str,
            sequence: int,
        ) -> AuditEntry: ...

        def _backlog_transition_matches(
            self,
            connection: sqlite3.Connection,
            run_id: str,
            item_id: str,
            expected_lease_id: str,
        ) -> bool: ...

        @staticmethod
        def _canonical_timestamp(value: datetime, name: str) -> str: ...

        def _require_stage_input(
            self,
            connection: sqlite3.Connection,
            ref: ArtifactRef,
            *,
            run_id: str,
            case_id: str,
            expected_sha256: str,
        ) -> None: ...

else:

    class SQLiteM3RepositoryHost:
        """Runtime-empty base; implementations are composed by the public façade."""
