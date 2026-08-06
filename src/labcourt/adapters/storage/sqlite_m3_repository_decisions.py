"""Atomic screening, verdict, review, Case, and audit authority."""

from __future__ import annotations

import sqlite3
from datetime import datetime

from labcourt.contracts.audit import AuditEntry, AuditEntryDraft, validate_audit_chain
from labcourt.contracts.backlog import (
    BacklogCompletionReceipt,
    BacklogItem,
    BacklogRetryContext,
    BacklogRetryFailure,
    BacklogRetrySuccess,
)
from labcourt.contracts.cases import Case, TimelineEntry, UsageSummary
from labcourt.contracts.enums import (
    ArtifactKind,
    AuditAction,
    AuditActorRole,
    BacklogReasonCode,
    BacklogStatus,
    CaseStatus,
    ScreeningDecision,
)
from labcourt.contracts.events import derive_case_id
from labcourt.contracts.evidence import EvidencePack
from labcourt.contracts.m3_operations import MAX_M3_PROCESS_CASES
from labcourt.contracts.model_call_failures import (
    ModelCallFailureClosureKind,
)
from labcourt.contracts.references import require_reference_token
from labcourt.contracts.screening import (
    ScreeningResult,
)
from labcourt.contracts.storage import ArtifactRef, ClosureReport
from labcourt.contracts.verdicts import ProceduralDefect, ProceduralReview, Verdict
from labcourt.exceptions import (
    ConcurrentModification,
    ContractViolation,
    ManifestMismatch,
)
from labcourt.ports.evidence_repository import AuditHead, CaseSnapshot
from labcourt.ports.screening_repository import (
    M3BacklogRetryCommit,
    M3CaseCommit,
    ModelCallFailureIntent,
)

from ._sqlite_read_session import SQLiteReadSession
from .sqlite_m3_repository_host import SQLiteM3RepositoryHost
from .sqlite_m3_repository_support import (
    _load_document,
    _require_sha256,
    _validated_copy,
)
from .sqlite_repository import (
    RepositoryIntegrityError,
    _audit_entry_from_row,
    _canonical_utc_timestamp,
    _document,
    _row_int,
    _row_optional_int,
    _row_optional_str,
    _row_str,
)


class SQLiteM3DecisionRepository(SQLiteM3RepositoryHost):
    """Atomic screening, verdict, review, Case, and audit authority."""

    def commit_screening(
        self,
        run_id: str,
        expected_revision: int,
        expected_audit_head: AuditHead,
        current_pack_closure: ClosureReport,
        screening: ScreeningResult,
    ) -> M3CaseCommit:
        """Commit one routed screening result and Case transition atomically."""

        require_reference_token(run_id, "repository run_id")
        self._require_expected_revision(expected_revision)
        validated = _validated_copy(screening, ScreeningResult)
        if validated.run_id != run_id:
            raise ContractViolation("screening result belongs to another run")
        result_json, result_sha256 = _document(validated)

        with self._immediate() as connection:
            existing = self._find_screening_collision(connection, validated)
            if existing is not None:
                if existing != validated:
                    raise RepositoryIntegrityError(
                        "screening identity or case version already binds different content"
                    )
                snapshot = self._load_case(connection, run_id, validated.case_id)
                if validated not in snapshot.case.screening_results:
                    raise RepositoryIntegrityError(
                        "screening row is not present in the authoritative Case version"
                    )
                parse_history = self._load_parse_history_for_output(
                    connection,
                    run_id,
                    validated.parsed_output.parsed_output_id,
                )
                self._reverify_parse_history_raw(
                    connection,
                    run_id=run_id,
                    parse_history=parse_history,
                )
                return M3CaseCommit(case=snapshot, created=False)

            snapshot = self._load_case(connection, run_id, validated.case_id)
            self._require_commit_guards(
                connection,
                snapshot=snapshot,
                expected_revision=expected_revision,
                expected_audit_head=expected_audit_head,
                current_pack_closure=current_pack_closure,
                pack_id=validated.evidence_pack_id,
                pack_version=validated.evidence_pack_version,
            )
            if snapshot.case.status != CaseStatus.EVIDENCE_READY:
                raise ConcurrentModification("new screening requires an EVIDENCE_READY Case")
            if validated.version != len(snapshot.case.screening_results) + 1:
                raise ConcurrentModification(
                    "screening version is not the next Case screening version"
                )
            parsed = self._load_parsed_output(
                connection,
                run_id,
                validated.parsed_output.parsed_output_id,
            )
            if parsed != validated.parsed_output:
                raise RepositoryIntegrityError(
                    "screening parsed output differs from its persisted root"
                )
            if any(
                prior.parsed_output.parsed_output_id == validated.parsed_output.parsed_output_id
                for prior in snapshot.case.screening_results
            ):
                raise RepositoryIntegrityError(
                    "parsed output is already consumed by a prior Case screening"
                )
            verifier = self._semantic_verifier
            if verifier is None:
                raise ContractViolation("new screening commits require a semantic_verifier")
            current_pack = self._load_pack(
                connection,
                run_id,
                validated.evidence_pack_id,
            )
            try:
                authoritative_screening = verifier.rebuild_screening(
                    parsed_output=parsed,
                    evidence_pack=current_pack,
                    screening_version=validated.version,
                )
            except (TypeError, ValueError) as exc:
                raise ContractViolation("trusted screening reconstruction failed") from exc
            if not isinstance(authoritative_screening, ScreeningResult):
                raise ContractViolation(
                    "semantic_verifier must return a ScreeningResult for screening"
                )
            if authoritative_screening != validated:
                raise ContractViolation("proposed screening differs from trusted reconstruction")
            parse_history = self._load_parse_history_for_output(
                connection,
                run_id,
                validated.parsed_output.parsed_output_id,
            )
            self._reverify_parse_history_raw(
                connection,
                run_id=run_id,
                parse_history=parse_history,
            )
            usage_delta = self._consume_model_call_usage(
                connection,
                run_id=run_id,
                case_id=validated.case_id,
                response_ids=tuple(receipt.response_id for receipt in parse_history),
                case_revision=snapshot.revision + 1,
                consumer_kind=ArtifactKind.SCREENING_RESULT,
                consumer_id=validated.screening_id,
            )
            status = (
                CaseStatus.ESCALATED
                if validated.decision == ScreeningDecision.ESCALATE
                else CaseStatus.SCREENED
            )
            new_case = self._case_with_updates(
                snapshot.case,
                status=status,
                usage=self._add_usage(snapshot.case.usage, usage_delta),
                screening_results=(*snapshot.case.screening_results, validated),
                timeline_entry=TimelineEntry(
                    sequence=len(snapshot.case.timeline),
                    action=AuditAction.CASE_STATE_CHANGED.value,
                    stage="SCREENING",
                    object_ref=validated.screening_id,
                    details={"decision": validated.decision.value},
                ),
            )
            head = self._validated_head(connection, run_id)
            self._require_expected_head(head, expected_audit_head)
            audit_sequence = head.sequence + 1
            connection.execute(
                """
                INSERT INTO screening_results(
                    run_id, screening_id, case_id, version,
                    evidence_pack_id, evidence_pack_version,
                    parsed_output_id, decision, manifest_id,
                    audit_sequence, result_json, document_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    validated.screening_id,
                    validated.case_id,
                    validated.version,
                    validated.evidence_pack_id,
                    validated.evidence_pack_version,
                    validated.parsed_output.parsed_output_id,
                    validated.decision.value,
                    validated.manifest_id,
                    audit_sequence,
                    result_json,
                    result_sha256,
                ),
            )
            committed = self._commit_case_version(
                connection,
                previous=snapshot,
                new_case=new_case,
                expected_head=head,
                object_ref=ArtifactRef(
                    kind=ArtifactKind.SCREENING_RESULT,
                    artifact_id=validated.screening_id,
                ),
            )
            return M3CaseCommit(case=committed, created=True)

    def commit_backlog_screening_success(
        self,
        run_id: str,
        expected_revision: int,
        expected_audit_head: AuditHead,
        current_pack_closure: ClosureReport,
        success: BacklogRetrySuccess,
        screening: ScreeningResult,
    ) -> M3BacklogRetryCommit:
        """Atomically complete a leased retry with an escalating screening."""

        require_reference_token(run_id, "repository run_id")
        self._require_expected_revision(expected_revision)
        validated_success = _validated_copy(success, BacklogRetrySuccess)
        validated_screening = _validated_copy(screening, ScreeningResult)
        if validated_success.lease.run_id != run_id or validated_screening.run_id != run_id:
            raise ContractViolation("backlog screening success belongs to another run")
        if (
            validated_success.completion_case_status != CaseStatus.ESCALATED
            or validated_success.completion_ref
            != ArtifactRef(
                kind=ArtifactKind.SCREENING_RESULT,
                artifact_id=validated_screening.screening_id,
            )
            or validated_screening.decision != ScreeningDecision.ESCALATE
        ):
            raise ContractViolation(
                "backlog screening success must complete with one escalating screening"
            )

        with self._immediate() as connection:
            replay = self._load_backlog_retry_replay(connection, validated_success)
            if replay is not None:
                if (
                    self._load_screening(
                        connection,
                        run_id,
                        validated_screening.screening_id,
                    )
                    != validated_screening
                ):
                    raise RepositoryIntegrityError(
                        "retry replay screening differs from immutable authority"
                    )
                replay_history = self._load_parse_history_for_output(
                    connection,
                    run_id,
                    validated_screening.parsed_output.parsed_output_id,
                )
                if (
                    self._parse_history_response_refs(replay_history)
                    != validated_success.response_refs
                ):
                    raise RepositoryIntegrityError(
                        "retry replay response refs differ from screening history"
                    )
                self._require_retry_parse_context(
                    connection,
                    run_id=run_id,
                    parse_history=replay_history,
                    lease=validated_success.lease,
                )
                return replay
            current, snapshot = self._require_active_backlog_lease(
                connection,
                run_id=run_id,
                lease=validated_success.lease,
                manifest_id=validated_success.manifest_id,
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
            )
            if (
                current.stage.value != "SCREENING"
                or validated_screening.case_id != current.case_id
                or validated_screening.manifest_id != current.manifest_id
                or validated_screening.evidence_pack_id != current_pack.pack_id
                or validated_screening.evidence_pack_version != current_pack.version
                or validated_screening.version != len(snapshot.case.screening_results) + 1
            ):
                raise ContractViolation(
                    "retry screening differs from the current backlog Case input"
                )
            if any(
                prior.parsed_output.parsed_output_id
                == validated_screening.parsed_output.parsed_output_id
                for prior in snapshot.case.screening_results
            ):
                raise ContractViolation("retry screening parsed output was already consumed")
            parsed = self._load_parsed_output(
                connection,
                run_id,
                validated_screening.parsed_output.parsed_output_id,
            )
            if parsed != validated_screening.parsed_output:
                raise RepositoryIntegrityError(
                    "retry screening differs from its persisted parsed output"
                )
            semantic = self._semantic_verifier
            if semantic is None:
                raise ContractViolation("backlog screening success requires a semantic_verifier")
            try:
                authoritative = semantic.rebuild_screening(
                    parsed_output=parsed,
                    evidence_pack=current_pack,
                    screening_version=validated_screening.version,
                )
            except (TypeError, ValueError) as exc:
                raise ContractViolation("trusted retry screening reconstruction failed") from exc
            if (
                not isinstance(authoritative, ScreeningResult)
                or authoritative != validated_screening
            ):
                raise ContractViolation("retry screening differs from trusted reconstruction")
            parse_history = self._load_parse_history_for_output(
                connection,
                run_id,
                parsed.parsed_output_id,
            )
            if self._parse_history_response_refs(parse_history) != validated_success.response_refs:
                raise ContractViolation(
                    "backlog success response refs must exactly match parse history"
                )
            self._require_retry_parse_context(
                connection,
                run_id=run_id,
                parse_history=parse_history,
                lease=validated_success.lease,
            )
            self._reverify_parse_history_raw(
                connection,
                run_id=run_id,
                parse_history=parse_history,
            )
            usage_ids = self._new_backlog_usage_response_ids(
                connection,
                snapshot=snapshot,
                response_ids=tuple(ref.artifact_id for ref in validated_success.response_refs),
                backlog_item_id=current.item_id,
            )
            usage_delta = self._consume_model_call_usage(
                connection,
                run_id=run_id,
                case_id=current.case_id,
                response_ids=usage_ids,
                case_revision=snapshot.revision + 1,
                consumer_kind=ArtifactKind.SCREENING_RESULT,
                consumer_id=validated_screening.screening_id,
            )
            completed_item = BacklogItem.model_validate(
                {
                    **current.model_dump(mode="json", exclude_computed_fields=True),
                    "status": BacklogStatus.COMPLETED.value,
                    "lease_id": None,
                    "lease_owner_sha256": None,
                    "lease_expires_at": None,
                }
            )
            new_case = self._case_with_updates(
                snapshot.case,
                status=CaseStatus.ESCALATED,
                usage=self._add_usage(snapshot.case.usage, usage_delta),
                screening_results=(*snapshot.case.screening_results, validated_screening),
                timeline_entry=TimelineEntry(
                    sequence=len(snapshot.case.timeline),
                    action=AuditAction.CASE_STATE_CHANGED.value,
                    stage="BACKLOG",
                    object_ref=validated_screening.screening_id,
                    details={
                        "outcome": "SUCCESS",
                        "item_id": current.item_id,
                        "decision": validated_screening.decision.value,
                    },
                ),
            )
            head = self._validated_head(connection, run_id)
            self._require_expected_head(head, expected_audit_head)
            audit_sequence = head.sequence + 1
            self._insert_screening_root(
                connection,
                validated_screening,
                audit_sequence=audit_sequence,
            )
            backlog_version = self._advance_backlog(
                connection,
                current,
                completed_item,
            )
            committed = self._commit_case_version(
                connection,
                previous=snapshot,
                new_case=new_case,
                expected_head=head,
                object_ref=validated_success.completion_ref,
            )
            audit = self._load_audit_entry(connection, run_id, audit_sequence)
            receipt = BacklogCompletionReceipt(
                outcome=validated_success,
                backlog_status=BacklogStatus.COMPLETED,
                completion_ref=validated_success.completion_ref,
                completion_case_status=CaseStatus.ESCALATED,
                completion_case_revision=committed.revision,
                completion_audit_sequence=audit.sequence,
                completion_audit_entry_hash=audit.entry_hash,
                manifest_id=validated_success.manifest_id,
            )
            self._insert_backlog_completion_receipt(
                connection,
                item=completed_item,
                backlog_version=backlog_version,
                receipt=receipt,
            )
            return M3BacklogRetryCommit(
                case=committed,
                item=completed_item,
                receipt=receipt,
                created=True,
            )

    def commit_verdict_review(
        self,
        run_id: str,
        expected_revision: int,
        expected_audit_head: AuditHead,
        current_pack_closure: ClosureReport,
        verdict: Verdict,
        review: ProceduralReview,
    ) -> M3CaseCommit:
        """Commit a verdict, its independent review, all defects, and Case atomically."""

        require_reference_token(run_id, "repository run_id")
        self._require_expected_revision(expected_revision)
        validated_verdict = _validated_copy(verdict, Verdict)
        validated_review = _validated_copy(review, ProceduralReview)
        self._validate_verdict_review_binding(
            run_id,
            validated_verdict,
            validated_review,
        )
        verdict_json, verdict_document_sha256 = _document(validated_verdict)
        review_json, review_document_sha256 = _document(validated_review)

        with self._immediate() as connection:
            existing_verdict = self._find_verdict_collision(connection, validated_verdict)
            existing_review = self._find_review_collision(connection, validated_review)
            if existing_verdict is not None or existing_review is not None:
                if existing_verdict != validated_verdict or existing_review != validated_review:
                    raise RepositoryIntegrityError(
                        "verdict/review identity or version already binds different content"
                    )
                snapshot = self._load_case(connection, run_id, validated_verdict.case_id)
                if (
                    validated_verdict not in snapshot.case.verdicts
                    or validated_review not in snapshot.case.procedural_reviews
                ):
                    raise RepositoryIntegrityError(
                        "verdict/review rows are absent from the authoritative Case version"
                    )
                screening = self._load_screening(
                    connection,
                    run_id,
                    validated_verdict.screening_id,
                )
                parse_history = self._load_parse_history_for_output(
                    connection,
                    run_id,
                    screening.parsed_output.parsed_output_id,
                )
                self._reverify_parse_history_raw(
                    connection,
                    run_id=run_id,
                    parse_history=parse_history,
                )
                return M3CaseCommit(case=snapshot, created=False)

            snapshot = self._load_case(connection, run_id, validated_verdict.case_id)
            self._require_commit_guards(
                connection,
                snapshot=snapshot,
                expected_revision=expected_revision,
                expected_audit_head=expected_audit_head,
                current_pack_closure=current_pack_closure,
                pack_id=validated_verdict.evidence_pack_id,
                pack_version=validated_verdict.evidence_pack_version,
            )
            if snapshot.case.status != CaseStatus.SCREENED:
                raise ConcurrentModification("new verdict and review require a SCREENED Case")
            if validated_verdict.version != len(snapshot.case.verdicts) + 1:
                raise ConcurrentModification("verdict version is not the next Case version")
            if validated_review.version != len(snapshot.case.procedural_reviews) + 1:
                raise ConcurrentModification(
                    "procedural review version is not the next Case review version"
                )
            screening = self._load_screening(
                connection,
                run_id,
                validated_verdict.screening_id,
            )
            if screening not in snapshot.case.screening_results:
                raise RepositoryIntegrityError(
                    "verdict screening root is absent from the authoritative Case"
                )
            if snapshot.case.screening_results[-1] != screening:
                raise ConcurrentModification(
                    "verdict must consume the latest Case screening result"
                )
            parse_history = self._load_parse_history_for_output(
                connection,
                run_id,
                screening.parsed_output.parsed_output_id,
            )
            expected_response_refs = tuple(
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
            if validated_verdict.model_response_refs != expected_response_refs:
                raise ContractViolation(
                    "verdict model response refs must exactly match the parse history"
                )
            verifier = self._procedural_review_verifier
            if verifier is None:
                raise ContractViolation("new verdict commits require a procedural_review_verifier")
            current_pack = self._load_pack(
                connection,
                run_id,
                validated_verdict.evidence_pack_id,
            )
            semantic_verifier = self._semantic_verifier
            if semantic_verifier is None:
                raise ContractViolation("new verdict commits require a semantic_verifier")
            try:
                authoritative_verdict = semantic_verifier.rebuild_fast_verdict(
                    screening_result=screening,
                    evidence_pack=current_pack,
                    model_response_refs=expected_response_refs,
                    verdict_version=validated_verdict.version,
                )
            except (TypeError, ValueError) as exc:
                raise ContractViolation("trusted fast verdict reconstruction failed") from exc
            if not isinstance(authoritative_verdict, Verdict):
                raise ContractViolation("semantic_verifier must return a Verdict for fast verdict")
            if authoritative_verdict != validated_verdict:
                raise ContractViolation("proposed verdict differs from trusted reconstruction")
            try:
                authoritative_review = verifier.rebuild_review(
                    verdict=validated_verdict,
                    evidence_pack=current_pack,
                    current_closure=current_pack_closure,
                    parse_history=parse_history,
                    review_version=validated_review.version,
                )
            except (TypeError, ValueError) as exc:
                raise ContractViolation("trusted procedural review reconstruction failed") from exc
            if not isinstance(authoritative_review, ProceduralReview):
                raise ContractViolation("procedural_review_verifier must return a ProceduralReview")
            if authoritative_review != validated_review:
                raise ContractViolation(
                    "proposed procedural review differs from trusted reconstruction"
                )
            self._reverify_parse_history_raw(
                connection,
                run_id=run_id,
                parse_history=parse_history,
            )

            status = (
                CaseStatus.READY_FOR_ALERT_POLICY
                if validated_review.passed
                else CaseStatus.REWORK_REQUIRED
            )
            new_case = self._case_with_updates(
                snapshot.case,
                status=status,
                verdicts=(*snapshot.case.verdicts, validated_verdict),
                procedural_reviews=(
                    *snapshot.case.procedural_reviews,
                    validated_review,
                ),
                timeline_entry=TimelineEntry(
                    sequence=len(snapshot.case.timeline),
                    action=AuditAction.CASE_STATE_CHANGED.value,
                    stage="PROCEDURAL_GATE",
                    object_ref=validated_review.review_id,
                    details={
                        "passed": validated_review.passed,
                        "verdict_id": validated_verdict.verdict_id,
                    },
                ),
            )
            head = self._validated_head(connection, run_id)
            self._require_expected_head(head, expected_audit_head)
            audit_sequence = head.sequence + 1
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
                    run_id,
                    validated_verdict.verdict_id,
                    validated_verdict.case_id,
                    validated_verdict.version,
                    validated_verdict.screening_id,
                    validated_verdict.evidence_pack_id,
                    validated_verdict.evidence_pack_version,
                    validated_verdict.verdict_input_sha256,
                    validated_verdict.verdict_sha256,
                    validated_verdict.manifest_id,
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
                    run_id,
                    validated_review.review_id,
                    validated_review.case_id,
                    validated_review.version,
                    validated_review.evidence_pack_id,
                    validated_review.evidence_pack_version,
                    validated_review.reviewed_verdict_id,
                    validated_review.reviewed_verdict_version,
                    validated_review.reviewed_verdict_sha256,
                    int(validated_review.passed),
                    validated_review.manifest_id,
                    audit_sequence,
                    review_json,
                    review_document_sha256,
                ),
            )
            self._insert_defects(
                connection,
                run_id=run_id,
                owner_kind=ArtifactKind.PROCEDURAL_REVIEW,
                owner_id=validated_review.review_id,
                defects=validated_review.defects,
            )
            committed = self._commit_case_version(
                connection,
                previous=snapshot,
                new_case=new_case,
                expected_head=head,
                object_ref=ArtifactRef(
                    kind=ArtifactKind.PROCEDURAL_REVIEW,
                    artifact_id=validated_review.review_id,
                ),
            )
            return M3CaseCommit(case=committed, created=True)

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
    ) -> M3BacklogRetryCommit:
        """Atomically complete a retry through screening, verdict, and review."""

        require_reference_token(run_id, "repository run_id")
        self._require_expected_revision(expected_revision)
        validated_success = _validated_copy(success, BacklogRetrySuccess)
        validated_verdict = _validated_copy(verdict, Verdict)
        validated_review = _validated_copy(review, ProceduralReview)
        validated_screening = (
            _validated_copy(screening, ScreeningResult) if screening is not None else None
        )
        self._validate_verdict_review_binding(run_id, validated_verdict, validated_review)
        expected_status = (
            CaseStatus.READY_FOR_ALERT_POLICY
            if validated_review.passed
            else CaseStatus.REWORK_REQUIRED
        )
        if (
            validated_success.lease.run_id != run_id
            or validated_success.completion_case_status != expected_status
            or validated_success.completion_ref
            != ArtifactRef(
                kind=ArtifactKind.PROCEDURAL_REVIEW,
                artifact_id=validated_review.review_id,
            )
        ):
            raise ContractViolation(
                "backlog verdict/review success conflicts with its completion target"
            )

        with self._immediate() as connection:
            replay = self._load_backlog_retry_replay(connection, validated_success)
            if replay is not None:
                if (
                    self._load_verdict(
                        connection,
                        run_id,
                        validated_verdict.verdict_id,
                    )
                    != validated_verdict
                    or self._load_review(
                        connection,
                        run_id,
                        validated_review.review_id,
                    )
                    != validated_review
                ):
                    raise RepositoryIntegrityError(
                        "retry replay verdict/review differs from immutable authority"
                    )
                if validated_screening is not None:
                    if (
                        self._load_screening(
                            connection,
                            run_id,
                            validated_screening.screening_id,
                        )
                        != validated_screening
                    ):
                        raise RepositoryIntegrityError(
                            "retry replay screening differs from immutable authority"
                        )
                    replay_history = self._load_parse_history_for_output(
                        connection,
                        run_id,
                        validated_screening.parsed_output.parsed_output_id,
                    )
                    self._require_retry_parse_context(
                        connection,
                        run_id=run_id,
                        parse_history=replay_history,
                        lease=validated_success.lease,
                    )
                return replay
            current, snapshot = self._require_active_backlog_lease(
                connection,
                run_id=run_id,
                lease=validated_success.lease,
                manifest_id=validated_success.manifest_id,
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
            )
            if current.stage.value != "SCREENING":
                raise ContractViolation("M3 retry success requires SCREENING backlog work")

            new_screening = validated_screening is not None
            if new_screening:
                assert validated_screening is not None
                if snapshot.case.screening_results:
                    raise ContractViolation(
                        "a BACKLOGGED Case with screening authority cannot append another "
                        "screening in verdict/review recovery"
                    )
                if (
                    validated_screening.run_id != run_id
                    or validated_screening.case_id != current.case_id
                    or validated_screening.manifest_id != current.manifest_id
                    or validated_screening.evidence_pack_id != current_pack.pack_id
                    or validated_screening.evidence_pack_version != current_pack.version
                    or validated_screening.version != 1
                    or validated_screening.decision == ScreeningDecision.ESCALATE
                ):
                    raise ContractViolation(
                        "retry screening cannot feed the proposed verdict/review"
                    )
                parsed = self._load_parsed_output(
                    connection,
                    run_id,
                    validated_screening.parsed_output.parsed_output_id,
                )
                if parsed != validated_screening.parsed_output:
                    raise RepositoryIntegrityError(
                        "retry screening differs from its parsed output authority"
                    )
                semantic = self._semantic_verifier
                if semantic is None:
                    raise ContractViolation("backlog verdict success requires a semantic_verifier")
                try:
                    authoritative_screening = semantic.rebuild_screening(
                        parsed_output=parsed,
                        evidence_pack=current_pack,
                        screening_version=validated_screening.version,
                    )
                except (TypeError, ValueError) as exc:
                    raise ContractViolation(
                        "trusted retry screening reconstruction failed"
                    ) from exc
                if (
                    not isinstance(authoritative_screening, ScreeningResult)
                    or authoritative_screening != validated_screening
                ):
                    raise ContractViolation("retry screening differs from trusted reconstruction")
                active_screening = validated_screening
            else:
                if (
                    current.reason_code != BacklogReasonCode.RESPONSE_INTEGRITY_FAILURE
                    or not snapshot.case.screening_results
                ):
                    raise ContractViolation(
                        "screening-free retry success requires existing raw-integrity "
                        "screening authority"
                    )
                active_screening = snapshot.case.screening_results[-1]
                persisted_screening = self._load_screening(
                    connection,
                    run_id,
                    active_screening.screening_id,
                )
                if persisted_screening != active_screening:
                    raise RepositoryIntegrityError(
                        "existing retry screening differs from immutable authority"
                    )

            parse_history = self._load_parse_history_for_output(
                connection,
                run_id,
                active_screening.parsed_output.parsed_output_id,
            )
            response_refs = self._parse_history_response_refs(parse_history)
            if validated_success.response_refs != response_refs:
                raise ContractViolation(
                    "backlog success response refs must exactly match screening history"
                )
            if new_screening:
                self._require_retry_parse_context(
                    connection,
                    run_id=run_id,
                    parse_history=parse_history,
                    lease=validated_success.lease,
                )
            self._reverify_parse_history_raw(
                connection,
                run_id=run_id,
                parse_history=parse_history,
            )
            usage_ids = self._new_backlog_usage_response_ids(
                connection,
                snapshot=snapshot,
                response_ids=tuple(ref.artifact_id for ref in response_refs),
                backlog_item_id=current.item_id,
            )
            if not new_screening and usage_ids:
                raise RepositoryIntegrityError(
                    "existing screening parse history lacks usage authority"
                )
            usage_delta = self._consume_model_call_usage(
                connection,
                run_id=run_id,
                case_id=current.case_id,
                response_ids=usage_ids,
                case_revision=snapshot.revision + 1,
                consumer_kind=ArtifactKind.SCREENING_RESULT,
                consumer_id=active_screening.screening_id,
            )

            if (
                validated_verdict.case_id != current.case_id
                or validated_verdict.manifest_id != current.manifest_id
                or validated_verdict.screening_id != active_screening.screening_id
                or validated_verdict.evidence_pack_id != current_pack.pack_id
                or validated_verdict.evidence_pack_version != current_pack.version
                or validated_verdict.version != len(snapshot.case.verdicts) + 1
                or validated_review.version != len(snapshot.case.procedural_reviews) + 1
                or validated_verdict.model_response_refs != response_refs
            ):
                raise ContractViolation("retry verdict/review differs from the current Case input")
            semantic = self._semantic_verifier
            procedural = self._procedural_review_verifier
            if semantic is None or procedural is None:
                raise ContractViolation(
                    "backlog verdict success requires semantic and procedural verifiers"
                )
            try:
                authoritative_verdict = semantic.rebuild_fast_verdict(
                    screening_result=active_screening,
                    evidence_pack=current_pack,
                    model_response_refs=response_refs,
                    verdict_version=validated_verdict.version,
                )
                authoritative_review = procedural.rebuild_review(
                    verdict=validated_verdict,
                    evidence_pack=current_pack,
                    current_closure=current_pack_closure,
                    parse_history=parse_history,
                    review_version=validated_review.version,
                )
            except (TypeError, ValueError) as exc:
                raise ContractViolation(
                    "trusted retry verdict/review reconstruction failed"
                ) from exc
            if (
                not isinstance(authoritative_verdict, Verdict)
                or authoritative_verdict != validated_verdict
                or not isinstance(authoritative_review, ProceduralReview)
                or authoritative_review != validated_review
            ):
                raise ContractViolation("retry verdict/review differs from trusted reconstruction")

            completed_item = BacklogItem.model_validate(
                {
                    **current.model_dump(mode="json", exclude_computed_fields=True),
                    "status": BacklogStatus.COMPLETED.value,
                    "lease_id": None,
                    "lease_owner_sha256": None,
                    "lease_expires_at": None,
                }
            )
            screenings = (
                (*snapshot.case.screening_results, active_screening)
                if new_screening
                else snapshot.case.screening_results
            )
            new_case = self._case_with_updates(
                snapshot.case,
                status=expected_status,
                usage=self._add_usage(snapshot.case.usage, usage_delta),
                screening_results=screenings,
                verdicts=(*snapshot.case.verdicts, validated_verdict),
                procedural_reviews=(
                    *snapshot.case.procedural_reviews,
                    validated_review,
                ),
                timeline_entry=TimelineEntry(
                    sequence=len(snapshot.case.timeline),
                    action=AuditAction.CASE_STATE_CHANGED.value,
                    stage="BACKLOG",
                    object_ref=validated_review.review_id,
                    details={
                        "outcome": "SUCCESS",
                        "item_id": current.item_id,
                        "passed": validated_review.passed,
                    },
                ),
            )
            head = self._validated_head(connection, run_id)
            self._require_expected_head(head, expected_audit_head)
            audit_sequence = head.sequence + 1
            if new_screening:
                self._insert_screening_root(
                    connection,
                    active_screening,
                    audit_sequence=audit_sequence,
                )
            self._insert_verdict_review_roots(
                connection,
                validated_verdict,
                validated_review,
                audit_sequence=audit_sequence,
            )
            backlog_version = self._advance_backlog(
                connection,
                current,
                completed_item,
            )
            committed = self._commit_case_version(
                connection,
                previous=snapshot,
                new_case=new_case,
                expected_head=head,
                object_ref=validated_success.completion_ref,
            )
            audit = self._load_audit_entry(connection, run_id, audit_sequence)
            receipt = BacklogCompletionReceipt(
                outcome=validated_success,
                backlog_status=BacklogStatus.COMPLETED,
                completion_ref=validated_success.completion_ref,
                completion_case_status=expected_status,
                completion_case_revision=committed.revision,
                completion_audit_sequence=audit.sequence,
                completion_audit_entry_hash=audit.entry_hash,
                manifest_id=validated_success.manifest_id,
            )
            self._insert_backlog_completion_receipt(
                connection,
                item=completed_item,
                backlog_version=backlog_version,
                receipt=receipt,
            )
            return M3BacklogRetryCommit(
                case=committed,
                item=completed_item,
                receipt=receipt,
                created=True,
            )

    def commit_backlog_retry_failure(
        self,
        run_id: str,
        expected_revision: int,
        expected_audit_head: AuditHead,
        current_pack_closure: ClosureReport,
        failure: BacklogRetryFailure,
        model_call_failure: ModelCallFailureIntent | None = None,
    ) -> M3BacklogRetryCommit:
        """Atomically account one proven retry failure and its Case transition."""

        require_reference_token(run_id, "repository run_id")
        self._require_expected_revision(expected_revision)
        validated = _validated_copy(failure, BacklogRetryFailure)
        if validated.lease.run_id != run_id:
            raise ContractViolation("backlog retry failure belongs to another run")
        if validated.reason_code == BacklogReasonCode.WORKER_LEASE_EXPIRED:
            raise ContractViolation(
                "WORKER_LEASE_EXPIRED is reserved for atomic reclaim_expired recovery"
            )

        with self._immediate() as connection:
            replay = self._load_backlog_retry_replay(connection, validated)
            if replay is not None:
                if validated.strict_parse_failure is not None:
                    self._require_strict_parse_failure_proof(
                        connection,
                        item=replay.item,
                        proof=validated.strict_parse_failure,
                    )
                if model_call_failure is not None:
                    self._require_model_call_failure_replay(
                        connection,
                        intent=model_call_failure,
                        item=replay.item,
                        closure_kind=ModelCallFailureClosureKind.RETRY_FAILURE,
                        receipt=replay.receipt,
                    )
                return replay
            current, snapshot = self._require_active_backlog_lease(
                connection,
                run_id=run_id,
                lease=validated.lease,
                manifest_id=validated.manifest_id,
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
            expected_status = (
                BacklogStatus.EXHAUSTED
                if current.attempt_count == current.max_attempts
                else BacklogStatus.PENDING
            )
            if validated.next_status != expected_status:
                raise ContractViolation(
                    "backlog retry failure status conflicts with its attempt budget"
                )
            response_ids = tuple(ref.artifact_id for ref in validated.response_refs)
            self._reverify_backlog_responses(
                connection,
                run_id=run_id,
                response_ids=response_ids,
                reason_code=validated.reason_code,
            )
            if validated.strict_parse_failure is not None:
                self._require_strict_parse_failure_proof(
                    connection,
                    item=current,
                    proof=validated.strict_parse_failure,
                )
            usage_ids = self._new_backlog_usage_response_ids(
                connection,
                snapshot=snapshot,
                response_ids=response_ids,
                backlog_item_id=current.item_id,
            )
            expected_context = BacklogRetryContext(
                backlog_item_id=current.item_id,
                retry_generation=current.retry_generation,
            )
            for response_id in usage_ids:
                response = self._load_response(connection, run_id, response_id)
                request = self._request_for_response(connection, response)
                if request.backlog_retry_context != expected_context:
                    raise ContractViolation(
                        "retry failure response does not bind the exact backlog generation"
                    )
            usage_delta = self._consume_model_call_usage(
                connection,
                run_id=run_id,
                case_id=current.case_id,
                response_ids=usage_ids,
                case_revision=snapshot.revision + 1,
                consumer_kind=ArtifactKind.BACKLOG_ITEM,
                consumer_id=current.item_id,
            )
            updated = BacklogItem.model_validate(
                {
                    **current.model_dump(mode="json", exclude_computed_fields=True),
                    "retry_generation": validated.next_retry_generation,
                    "status": validated.next_status.value,
                    "lease_id": None,
                    "lease_owner_sha256": None,
                    "lease_expires_at": None,
                }
            )
            completion_ref = ArtifactRef(
                kind=ArtifactKind.BACKLOG_ITEM,
                artifact_id=current.item_id,
            )
            new_case = self._case_with_updates(
                snapshot.case,
                status=validated.completion_case_status,
                current_backlog_item_id=(
                    current.item_id if validated.next_status == BacklogStatus.PENDING else None
                ),
                usage=self._add_usage(snapshot.case.usage, usage_delta),
                timeline_entry=TimelineEntry(
                    sequence=len(snapshot.case.timeline),
                    action=AuditAction.CASE_STATE_CHANGED.value,
                    stage="BACKLOG",
                    object_ref=current.item_id,
                    details={
                        "outcome": "FAILURE",
                        "reason_code": validated.reason_code.value,
                        "status": validated.next_status.value,
                        "retry_generation": validated.next_retry_generation,
                    },
                ),
            )
            head = self._validated_head(connection, run_id)
            self._require_expected_head(head, expected_audit_head)
            audit_sequence = head.sequence + 1
            backlog_version = self._advance_backlog(connection, current, updated)
            committed = self._commit_case_version(
                connection,
                previous=snapshot,
                new_case=new_case,
                expected_head=head,
                object_ref=completion_ref,
            )
            audit = self._load_audit_entry(connection, run_id, audit_sequence)
            receipt = BacklogCompletionReceipt(
                outcome=validated,
                backlog_status=validated.next_status,
                completion_ref=completion_ref,
                completion_case_status=validated.completion_case_status,
                completion_case_revision=committed.revision,
                completion_audit_sequence=audit.sequence,
                completion_audit_entry_hash=audit.entry_hash,
                manifest_id=validated.manifest_id,
            )
            self._insert_backlog_completion_receipt(
                connection,
                item=updated,
                backlog_version=backlog_version,
                receipt=receipt,
            )
            if model_call_failure is not None:
                self._insert_model_call_failure_authority(
                    connection,
                    intent=model_call_failure,
                    item=updated,
                    backlog_version=backlog_version,
                    closure_kind=ModelCallFailureClosureKind.RETRY_FAILURE,
                    committed=committed,
                    audit=audit,
                    receipt=receipt,
                )
            return M3BacklogRetryCommit(
                case=committed,
                item=updated,
                receipt=receipt,
                created=True,
            )

    def load_case(self, run_id: str, case_id: str) -> CaseSnapshot:
        require_reference_token(run_id, "repository run_id")
        require_reference_token(case_id, "repository case_id")
        with self._read() as connection:
            return self._load_case(connection, run_id, case_id)

    def select_case_ids_bounded(
        self,
        run_id: str,
        limit: int,
    ) -> tuple[tuple[str, ...], int]:
        """Select at most ``limit`` IDs, prioritizing actionable M3 cases.

        ``COUNT(*)`` establishes the exact report inventory without materializing
        it.  ``EVIDENCE_READY`` and ``SCREENED`` cases are selected before all
        other states, with case ID as the stable tie-breaker.  Only the bounded
        IDs are loaded through the full Case/event authority verifier, so a large
        run cannot turn an operational batch into an unbounded Python allocation.
        """

        require_reference_token(run_id, "repository run_id")
        if (
            not isinstance(limit, int)
            or isinstance(limit, bool)
            or not 1 <= limit <= MAX_M3_PROCESS_CASES
        ):
            raise ValueError(
                f"bounded M3 case limit must be an integer from 1 through {MAX_M3_PROCESS_CASES}"
            )
        with self._read() as connection:
            self._validated_head(connection, run_id)
            count_row = connection.execute(
                "SELECT COUNT(*) AS case_count FROM cases WHERE run_id = ?",
                (run_id,),
            ).fetchone()
            if count_row is None:
                raise RepositoryIntegrityError("case inventory count returned no row")
            available_count = _row_int(count_row, "case_count")
            rows = connection.execute(
                """
                SELECT case_id, status FROM cases
                WHERE run_id = ?
                ORDER BY
                    CASE WHEN status IN (?, ?) THEN 0 ELSE 1 END,
                    case_id
                LIMIT ?
                """,
                (
                    run_id,
                    CaseStatus.EVIDENCE_READY.value,
                    CaseStatus.SCREENED.value,
                    limit,
                ),
            ).fetchall()
            selected: list[str] = []
            selection_keys: list[tuple[int, str]] = []
            for row in rows:
                indexed_case_id = _row_str(row, "case_id")
                indexed_status_value = _row_str(row, "status")
                snapshot = self._load_case(connection, run_id, indexed_case_id)
                derived_case_id = derive_case_id(snapshot.case.event.event_id)
                if derived_case_id != indexed_case_id:
                    raise RepositoryIntegrityError(
                        "case index differs from its authoritative event identity"
                    )
                if snapshot.case.status.value != indexed_status_value:
                    raise RepositoryIntegrityError(
                        "case index status differs from its authoritative version"
                    )
                selected.append(derived_case_id)
                priority = int(
                    snapshot.case.status not in {CaseStatus.EVIDENCE_READY, CaseStatus.SCREENED}
                )
                selection_keys.append((priority, derived_case_id))
            case_ids = tuple(selected)
            if (
                len(case_ids) > available_count
                or len(case_ids) != min(limit, available_count)
                or tuple(selection_keys) != tuple(sorted(selection_keys))
                or len(case_ids) != len(set(case_ids))
            ):
                raise RepositoryIntegrityError("bounded case selection is inconsistent")
            return case_ids, available_count

    def load_screening(self, run_id: str, screening_id: str) -> ScreeningResult:
        require_reference_token(run_id, "repository run_id")
        _require_sha256(screening_id, "screening_id")
        with self._read() as connection:
            return self._load_screening(connection, run_id, screening_id)

    def load_verdict(self, run_id: str, verdict_id: str) -> Verdict:
        require_reference_token(run_id, "repository run_id")
        _require_sha256(verdict_id, "verdict_id")
        with self._read() as connection:
            return self._load_verdict(connection, run_id, verdict_id)

    def load_procedural_review(self, run_id: str, review_id: str) -> ProceduralReview:
        require_reference_token(run_id, "repository run_id")
        _require_sha256(review_id, "review_id")
        with self._read() as connection:
            return self._load_review(connection, run_id, review_id)

    @staticmethod
    def _add_usage(current: UsageSummary, delta: UsageSummary) -> UsageSummary:
        return UsageSummary(
            input_images=current.input_images + delta.input_images,
            input_pixels=current.input_pixels + delta.input_pixels,
            input_tokens=current.input_tokens + delta.input_tokens,
            output_tokens=current.output_tokens + delta.output_tokens,
            provider_latency_ms=(current.provider_latency_ms + delta.provider_latency_ms),
            retries=current.retries + delta.retries,
            estimated_cost=current.estimated_cost + delta.estimated_cost,
        )

    def _insert_screening_root(
        self,
        connection: sqlite3.Connection,
        screening: ScreeningResult,
        *,
        audit_sequence: int,
    ) -> None:
        if self._find_screening_collision(connection, screening) is not None:
            raise ConcurrentModification(
                "screening identity or version was committed without this retry receipt"
            )
        result_json, result_sha256 = _document(screening)
        connection.execute(
            """
            INSERT INTO screening_results(
                run_id, screening_id, case_id, version,
                evidence_pack_id, evidence_pack_version,
                parsed_output_id, decision, manifest_id,
                audit_sequence, result_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                screening.run_id,
                screening.screening_id,
                screening.case_id,
                screening.version,
                screening.evidence_pack_id,
                screening.evidence_pack_version,
                screening.parsed_output.parsed_output_id,
                screening.decision.value,
                screening.manifest_id,
                audit_sequence,
                result_json,
                result_sha256,
            ),
        )

    def _insert_verdict_review_roots(
        self,
        connection: sqlite3.Connection,
        verdict: Verdict,
        review: ProceduralReview,
        *,
        audit_sequence: int,
    ) -> None:
        if (
            self._find_verdict_collision(connection, verdict) is not None
            or self._find_review_collision(connection, review) is not None
        ):
            raise ConcurrentModification(
                "verdict/review identity or version was committed without this retry receipt"
            )
        verdict_json, verdict_sha256 = _document(verdict)
        review_json, review_sha256 = _document(review)
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
                verdict_sha256,
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
                review_sha256,
            ),
        )
        self._insert_defects(
            connection,
            run_id=review.run_id,
            owner_kind=ArtifactKind.PROCEDURAL_REVIEW,
            owner_id=review.review_id,
            defects=review.defects,
        )

    def _insert_defects(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        owner_kind: ArtifactKind,
        owner_id: str,
        defects: tuple[ProceduralDefect, ...],
    ) -> None:
        if owner_kind not in {
            ArtifactKind.MODEL_PARSE_RECEIPT,
            ArtifactKind.PROCEDURAL_REVIEW,
        }:
            raise ValueError("defect owner kind is not persistent in M3")
        for ordinal, defect in enumerate(defects):
            defect_json, defect_sha256 = _document(defect)
            connection.execute(
                """
                INSERT INTO procedural_defects(
                    run_id, owner_kind, owner_id, ordinal, defect_id,
                    origin, code, artifact_kind, artifact_id,
                    parse_receipt_id, review_id,
                    defect_json, document_sha256
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    owner_kind.value,
                    owner_id,
                    ordinal,
                    defect.defect_id,
                    defect.origin.value,
                    defect.code.value,
                    defect.artifact_ref.kind.value,
                    defect.artifact_ref.artifact_id,
                    owner_id if owner_kind == ArtifactKind.MODEL_PARSE_RECEIPT else None,
                    owner_id if owner_kind == ArtifactKind.PROCEDURAL_REVIEW else None,
                    defect_json,
                    defect_sha256,
                ),
            )

    def _verify_defect_rows(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        owner_kind: ArtifactKind,
        owner_id: str,
        expected: tuple[ProceduralDefect, ...],
    ) -> None:
        rows = connection.execute(
            """
            SELECT * FROM procedural_defects
            WHERE run_id = ? AND owner_kind = ? AND owner_id = ?
            ORDER BY ordinal
            """,
            (run_id, owner_kind.value, owner_id),
        ).fetchall()
        defects = tuple(
            _load_document(
                row,
                json_key="defect_json",
                sha256_key="document_sha256",
                model_type=ProceduralDefect,
            )
            for row in rows
        )
        if defects != expected:
            raise RepositoryIntegrityError("procedural defect rows differ from their owning root")
        for ordinal, (row, defect) in enumerate(zip(rows, defects, strict=True)):
            parse_receipt_id = _row_optional_str(row, "parse_receipt_id")
            review_id = _row_optional_str(row, "review_id")
            indexed = (
                _row_str(row, "run_id"),
                _row_str(row, "owner_kind"),
                _row_str(row, "owner_id"),
                _row_int(row, "ordinal"),
                _row_str(row, "defect_id"),
                _row_str(row, "origin"),
                _row_str(row, "code"),
                _row_str(row, "artifact_kind"),
                _row_str(row, "artifact_id"),
                parse_receipt_id,
                review_id,
            )
            expected_index = (
                run_id,
                owner_kind.value,
                owner_id,
                ordinal,
                defect.defect_id,
                defect.origin.value,
                defect.code.value,
                defect.artifact_ref.kind.value,
                defect.artifact_ref.artifact_id,
                owner_id if owner_kind == ArtifactKind.MODEL_PARSE_RECEIPT else None,
                owner_id if owner_kind == ArtifactKind.PROCEDURAL_REVIEW else None,
            )
            if indexed != expected_index:
                raise RepositoryIntegrityError(
                    "procedural defect indexes differ from canonical content"
                )

    def _find_screening_collision(
        self,
        connection: sqlite3.Connection,
        screening: ScreeningResult,
    ) -> ScreeningResult | None:
        rows = connection.execute(
            """
            SELECT * FROM screening_results
            WHERE run_id = ?
              AND (screening_id = ? OR (case_id = ? AND version = ?))
            """,
            (
                screening.run_id,
                screening.screening_id,
                screening.case_id,
                screening.version,
            ),
        ).fetchall()
        if not rows:
            return None
        if len(rows) != 1:
            raise RepositoryIntegrityError("screening identity indexes select multiple rows")
        return self._screening_from_row(connection, rows[0])

    def _load_screening(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        screening_id: str,
    ) -> ScreeningResult:
        row = connection.execute(
            """
            SELECT * FROM screening_results
            WHERE run_id = ? AND screening_id = ?
            """,
            (run_id, screening_id),
        ).fetchone()
        if row is None:
            raise ContractViolation("unknown screening result")
        return self._screening_from_row(connection, row)

    def _screening_from_row(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> ScreeningResult:
        screening = _load_document(
            row,
            json_key="result_json",
            sha256_key="document_sha256",
            model_type=ScreeningResult,
        )
        indexed = (
            _row_str(row, "run_id"),
            _row_str(row, "screening_id"),
            _row_str(row, "case_id"),
            _row_int(row, "version"),
            _row_str(row, "evidence_pack_id"),
            _row_int(row, "evidence_pack_version"),
            _row_str(row, "parsed_output_id"),
            _row_str(row, "decision"),
            _row_str(row, "manifest_id"),
        )
        expected = (
            screening.run_id,
            screening.screening_id,
            screening.case_id,
            screening.version,
            screening.evidence_pack_id,
            screening.evidence_pack_version,
            screening.parsed_output.parsed_output_id,
            screening.decision.value,
            screening.manifest_id,
        )
        if indexed != expected:
            raise RepositoryIntegrityError("screening indexes differ from canonical content")
        output = self._load_parsed_output(
            connection,
            screening.run_id,
            screening.parsed_output.parsed_output_id,
        )
        if output != screening.parsed_output:
            raise RepositoryIntegrityError(
                "screening embeds a different parsed output than its persisted root"
            )
        return screening

    def _find_verdict_collision(
        self,
        connection: sqlite3.Connection,
        verdict: Verdict,
    ) -> Verdict | None:
        rows = connection.execute(
            """
            SELECT * FROM verdicts
            WHERE run_id = ?
              AND (verdict_id = ? OR (case_id = ? AND version = ?))
            """,
            (verdict.run_id, verdict.verdict_id, verdict.case_id, verdict.version),
        ).fetchall()
        if not rows:
            return None
        if len(rows) != 1:
            raise RepositoryIntegrityError("verdict indexes select multiple rows")
        return self._verdict_from_row(connection, rows[0])

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
            raise ContractViolation("unknown verdict")
        return self._verdict_from_row(connection, row)

    def _verdict_from_row(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> Verdict:
        verdict = _load_document(
            row,
            json_key="verdict_json",
            sha256_key="document_sha256",
            model_type=Verdict,
        )
        indexed = (
            _row_str(row, "run_id"),
            _row_str(row, "verdict_id"),
            _row_str(row, "case_id"),
            _row_int(row, "version"),
            _row_str(row, "screening_id"),
            _row_str(row, "evidence_pack_id"),
            _row_int(row, "evidence_pack_version"),
            _row_str(row, "verdict_input_sha256"),
            _row_str(row, "verdict_sha256"),
            _row_str(row, "manifest_id"),
        )
        expected = (
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
        )
        if indexed != expected:
            raise RepositoryIntegrityError("verdict indexes differ from canonical content")
        self._load_screening(connection, verdict.run_id, verdict.screening_id)
        return verdict

    def _find_review_collision(
        self,
        connection: sqlite3.Connection,
        review: ProceduralReview,
    ) -> ProceduralReview | None:
        rows = connection.execute(
            """
            SELECT * FROM procedural_reviews
            WHERE run_id = ?
              AND (review_id = ? OR (case_id = ? AND version = ?))
            """,
            (review.run_id, review.review_id, review.case_id, review.version),
        ).fetchall()
        if not rows:
            return None
        if len(rows) != 1:
            raise RepositoryIntegrityError("procedural review indexes select multiple rows")
        return self._review_from_row(connection, rows[0])

    def _load_review(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        review_id: str,
    ) -> ProceduralReview:
        row = connection.execute(
            """
            SELECT * FROM procedural_reviews
            WHERE run_id = ? AND review_id = ?
            """,
            (run_id, review_id),
        ).fetchone()
        if row is None:
            raise ContractViolation("unknown procedural review")
        return self._review_from_row(connection, row)

    def _review_from_row(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> ProceduralReview:
        review = _load_document(
            row,
            json_key="review_json",
            sha256_key="document_sha256",
            model_type=ProceduralReview,
        )
        indexed = (
            _row_str(row, "run_id"),
            _row_str(row, "review_id"),
            _row_str(row, "case_id"),
            _row_int(row, "version"),
            _row_str(row, "evidence_pack_id"),
            _row_int(row, "evidence_pack_version"),
            _row_str(row, "reviewed_verdict_id"),
            _row_int(row, "reviewed_verdict_version"),
            _row_str(row, "reviewed_verdict_sha256"),
            _row_int(row, "passed"),
            _row_str(row, "manifest_id"),
        )
        expected = (
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
        )
        if indexed != expected:
            raise RepositoryIntegrityError(
                "procedural review indexes differ from canonical content"
            )
        verdict = self._load_verdict(
            connection,
            review.run_id,
            review.reviewed_verdict_id,
        )
        if (
            verdict.case_id != review.case_id
            or verdict.version != review.reviewed_verdict_version
            or verdict.verdict_sha256 != review.reviewed_verdict_sha256
        ):
            raise RepositoryIntegrityError(
                "procedural review differs from its persisted verdict binding"
            )
        self._verify_defect_rows(
            connection,
            run_id=review.run_id,
            owner_kind=ArtifactKind.PROCEDURAL_REVIEW,
            owner_id=review.review_id,
            expected=review.defects,
        )
        return review

    @staticmethod
    def _require_expected_revision(expected_revision: int) -> None:
        if (
            not isinstance(expected_revision, int)
            or isinstance(expected_revision, bool)
            or expected_revision < 1
        ):
            raise ValueError("expected_revision must be a positive integer")

    def _load_case(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        case_id: str,
    ) -> CaseSnapshot:
        row = connection.execute(
            """
            SELECT c.current_revision, c.status, c.manifest_id,
                   c.latest_pack_id, c.latest_pack_version,
                   cv.status AS version_status,
                   cv.case_json, cv.document_sha256,
                   (
                       SELECT MAX(cv2.revision)
                       FROM case_versions AS cv2
                       WHERE cv2.run_id = c.run_id AND cv2.case_id = c.case_id
                   ) AS max_revision
            FROM cases AS c
            JOIN case_versions AS cv
              ON cv.run_id = c.run_id
             AND cv.case_id = c.case_id
             AND cv.revision = c.current_revision
            WHERE c.run_id = ? AND c.case_id = ?
            """,
            (run_id, case_id),
        ).fetchone()
        if row is None:
            raise ContractViolation("unknown case")
        case = _load_document(
            row,
            json_key="case_json",
            sha256_key="document_sha256",
            model_type=Case,
        )
        revision = _row_int(row, "current_revision")
        if revision != _row_int(row, "max_revision"):
            raise RepositoryIntegrityError("case head does not select its latest immutable version")
        latest = (
            (case.evidence_packs[-1].pack_id, case.evidence_packs[-1].version)
            if case.evidence_packs
            else (None, None)
        )
        indexed = (
            case.run_id,
            case.case_id,
            case.status.value,
            case.manifest_id,
            latest[0],
            latest[1],
        )
        expected = (
            run_id,
            case_id,
            _row_str(row, "status"),
            _row_str(row, "manifest_id"),
            _row_optional_str(row, "latest_pack_id"),
            _row_optional_int(row, "latest_pack_version"),
        )
        if indexed != expected or _row_str(row, "version_status") != case.status.value:
            raise RepositoryIntegrityError("case head indexes differ from its canonical version")
        self._verify_case_roots(connection, case)
        return CaseSnapshot(case=case, revision=revision)

    def _verify_case_roots(
        self,
        connection: sqlite3.Connection,
        case: Case,
        *,
        allow_future_roots: bool = False,
    ) -> None:
        screening_rows = connection.execute(
            """
            SELECT screening_id FROM screening_results
            WHERE run_id = ? AND case_id = ? ORDER BY version
            """,
            (case.run_id, case.case_id),
        ).fetchall()
        screening_ids = tuple(_row_str(row, "screening_id") for row in screening_rows)
        expected_screening_ids = tuple(item.screening_id for item in case.screening_results)
        visible_screening_ids = (
            screening_ids[: len(expected_screening_ids)] if allow_future_roots else screening_ids
        )
        if visible_screening_ids != expected_screening_ids:
            raise RepositoryIntegrityError(
                "Case screening history differs from immutable screening roots"
            )
        for screening_expected in case.screening_results:
            if (
                self._load_screening(
                    connection,
                    case.run_id,
                    screening_expected.screening_id,
                )
                != screening_expected
            ):
                raise RepositoryIntegrityError("Case embeds modified screening content")

        verdict_rows = connection.execute(
            """
            SELECT verdict_id FROM verdicts
            WHERE run_id = ? AND case_id = ? ORDER BY version
            """,
            (case.run_id, case.case_id),
        ).fetchall()
        verdict_ids = tuple(_row_str(row, "verdict_id") for row in verdict_rows)
        expected_verdict_ids = tuple(item.verdict_id for item in case.verdicts)
        visible_verdict_ids = (
            verdict_ids[: len(expected_verdict_ids)] if allow_future_roots else verdict_ids
        )
        if visible_verdict_ids != expected_verdict_ids:
            raise RepositoryIntegrityError(
                "Case verdict history differs from immutable verdict roots"
            )
        for verdict_expected in case.verdicts:
            if (
                self._load_verdict(connection, case.run_id, verdict_expected.verdict_id)
                != verdict_expected
            ):
                raise RepositoryIntegrityError("Case embeds modified verdict content")

        review_rows = connection.execute(
            """
            SELECT review_id FROM procedural_reviews
            WHERE run_id = ? AND case_id = ? ORDER BY version
            """,
            (case.run_id, case.case_id),
        ).fetchall()
        review_ids = tuple(_row_str(row, "review_id") for row in review_rows)
        expected_review_ids = tuple(item.review_id for item in case.procedural_reviews)
        visible_review_ids = (
            review_ids[: len(expected_review_ids)] if allow_future_roots else review_ids
        )
        if visible_review_ids != expected_review_ids:
            raise RepositoryIntegrityError(
                "Case review history differs from immutable review roots"
            )
        for review_expected in case.procedural_reviews:
            if (
                self._load_review(connection, case.run_id, review_expected.review_id)
                != review_expected
            ):
                raise RepositoryIntegrityError("Case embeds modified review content")

    def _load_pack(
        self,
        connection: sqlite3.Connection,
        run_id: str,
        pack_id: str,
    ) -> EvidencePack:
        row = connection.execute(
            """
            SELECT * FROM evidence_packs
            WHERE run_id = ? AND pack_id = ?
            """,
            (run_id, pack_id),
        ).fetchone()
        if row is None:
            raise ContractViolation("unknown evidence pack")
        pack = _load_document(
            row,
            json_key="pack_json",
            sha256_key="document_sha256",
            model_type=EvidencePack,
        )
        indexed = (
            _row_str(row, "run_id"),
            _row_str(row, "pack_id"),
            _row_str(row, "case_id"),
            _row_int(row, "version"),
            _row_str(row, "manifest_id"),
            _row_str(row, "closure_input_sha256"),
        )
        expected = (
            pack.run_id,
            pack.pack_id,
            pack.case_id,
            pack.version,
            pack.manifest_id,
            pack.closure_input_sha256,
        )
        if indexed != expected:
            raise RepositoryIntegrityError("evidence pack indexes differ from canonical content")
        return pack

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
    ) -> None:
        if snapshot.revision != expected_revision:
            raise ConcurrentModification(
                f"case revision is {snapshot.revision}, expected {expected_revision}"
            )
        head = self._validated_head(connection, snapshot.case.run_id)
        self._require_expected_head(head, expected_audit_head)
        expected_closure = self._require_current_pack_closure(
            connection,
            snapshot.case,
            pack_id,
            pack_version,
            current_pack_closure,
            require_passed=require_passed_closure,
        )
        self._reverify_current_pack(
            connection,
            case=snapshot.case,
            pack_id=pack_id,
            pack_version=pack_version,
            expected=expected_closure,
            require_passed=require_passed_closure,
        )

    def _require_current_pack_closure(
        self,
        connection: sqlite3.Connection,
        case: Case,
        pack_id: str,
        pack_version: int,
        report: ClosureReport,
        *,
        require_passed: bool,
    ) -> ClosureReport:
        validated = _validated_copy(report, ClosureReport)
        if require_passed and not validated.passed:
            raise ContractViolation("current evidence pack closure did not pass")
        if not case.evidence_packs:
            raise ConcurrentModification("case has no current evidence pack")
        current = case.evidence_packs[-1]
        if (current.pack_id, current.version) != (pack_id, pack_version):
            raise ConcurrentModification("M3 input no longer references the current pack")
        persisted = self._load_pack(connection, case.run_id, pack_id)
        if persisted != current or persisted.version != pack_version:
            raise RepositoryIntegrityError(
                "current Case evidence pack differs from its persisted root"
            )
        expected_root = ArtifactRef(kind=ArtifactKind.EVIDENCE_PACK, artifact_id=pack_id)
        expected_checked_by_key = {
            ref.sort_key: ref for ref in (*persisted.expected_closure_refs(), expected_root)
        }
        expected_checked = tuple(
            expected_checked_by_key[key] for key in sorted(expected_checked_by_key)
        )
        if (
            validated.run_id != case.run_id
            or validated.manifest_id != case.manifest_id
            or validated.root_ref != expected_root
            or validated.input_sha256 != persisted.closure_input_sha256
            or validated.checked_refs != expected_checked
        ):
            raise ContractViolation("closure report is not bound to the current evidence pack")
        return validated

    def _reverify_current_pack(
        self,
        connection: sqlite3.Connection,
        *,
        case: Case,
        pack_id: str,
        pack_version: int,
        expected: ClosureReport,
        require_passed: bool,
    ) -> None:
        """Re-run physical closure while the M3 write transaction owns its lock."""

        verifier = self._current_pack_verifier
        if verifier is None:
            raise ContractViolation("M3 aggregate commits require a current_pack_verifier")
        fresh_value = verifier(case.run_id, pack_id)
        if not isinstance(fresh_value, ClosureReport):
            raise ContractViolation("current_pack_verifier must return a ClosureReport")
        try:
            fresh = self._require_current_pack_closure(
                connection,
                case,
                pack_id,
                pack_version,
                fresh_value,
                require_passed=False,
            )
        except ContractViolation as exc:
            raise ConcurrentModification(
                "current evidence pack closure binding changed during M3 commit"
            ) from exc
        if require_passed and not fresh.passed:
            raise ConcurrentModification(
                "current evidence pack failed physical closure during M3 commit"
            )
        if fresh != expected:
            raise ConcurrentModification("current evidence pack closure changed during M3 commit")

    def _require_case_pack_scope(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        case_id: str,
        pack_id: str,
        pack_version: int,
        manifest_id: str,
    ) -> None:
        row = connection.execute(
            """
            SELECT 1
            FROM evidence_packs AS ep
            JOIN cases AS c
              ON c.run_id = ep.run_id AND c.case_id = ep.case_id
            WHERE ep.run_id = ? AND ep.case_id = ?
              AND ep.pack_id = ? AND ep.version = ?
              AND ep.manifest_id = ? AND c.manifest_id = ?
            """,
            (run_id, case_id, pack_id, pack_version, manifest_id, manifest_id),
        ).fetchone()
        if row is None:
            raise ManifestMismatch("M3 root does not match a persisted case/pack/manifest scope")

    def _require_case_manifest(
        self,
        connection: sqlite3.Connection,
        *,
        run_id: str,
        case_id: str,
        manifest_id: str,
    ) -> None:
        row = connection.execute(
            """
            SELECT 1 FROM cases
            WHERE run_id = ? AND case_id = ? AND manifest_id = ?
            """,
            (run_id, case_id, manifest_id),
        ).fetchone()
        if row is None:
            raise ManifestMismatch("backlog case or manifest binding does not exist")

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
    ) -> Case:
        payload = case.model_dump(mode="json", exclude_computed_fields=True)
        payload["status"] = status.value
        payload["current_backlog_item_id"] = current_backlog_item_id
        if usage is not None:
            payload["usage"] = usage.model_dump(mode="json")
        payload["timeline"] = [
            *(entry.model_dump(mode="json") for entry in case.timeline),
            timeline_entry.model_dump(mode="json"),
        ]
        if screening_results is not None:
            payload["screening_results"] = [
                item.model_dump(mode="json") for item in screening_results
            ]
        if verdicts is not None:
            payload["verdicts"] = [item.model_dump(mode="json") for item in verdicts]
        if procedural_reviews is not None:
            payload["procedural_reviews"] = [
                item.model_dump(mode="json") for item in procedural_reviews
            ]
        return Case.model_validate(payload)

    def _head(self, connection: SQLiteReadSession, run_id: str) -> AuditHead:
        row = connection.execute(
            """
            SELECT manifest_id, revision, audit_head_sequence, audit_head_hash
            FROM runs WHERE run_id = ?
            """,
            (run_id,),
        ).fetchone()
        if row is None:
            raise ContractViolation("unknown run")
        run_revision = _row_int(row, "revision")
        sequence = _row_int(row, "audit_head_sequence")
        entry_hash = _row_str(row, "audit_head_hash")
        if run_revision != sequence + 1:
            raise RepositoryIntegrityError("run revision and audit head are inconsistent")
        return AuditHead(
            run_id=run_id,
            manifest_id=_row_str(row, "manifest_id"),
            run_revision=run_revision,
            sequence=sequence,
            entry_hash=entry_hash,
        )

    def _validated_head(self, connection: SQLiteReadSession, run_id: str) -> AuditHead:
        head = self._head(connection, run_id)
        rows = connection.execute(
            "SELECT * FROM audit_entries WHERE run_id = ? ORDER BY sequence",
            (run_id,),
        ).fetchall()
        entries = tuple(_audit_entry_from_row(row) for row in rows)
        report = validate_audit_chain(
            entries,
            expected_run_id=run_id,
            expected_manifest_id=head.manifest_id,
            expected_head_sequence=head.sequence,
            expected_head_hash=head.entry_hash,
        )
        if not report.passed:
            raise RepositoryIntegrityError("cannot append to an invalid audit chain")
        return head

    @staticmethod
    def _require_expected_head(actual: AuditHead, expected: AuditHead) -> None:
        if not isinstance(expected, AuditHead):
            raise TypeError("expected_audit_head must be an AuditHead")
        if actual != expected:
            raise ConcurrentModification("run audit head changed before M3 commit")

    def _recorded_at(self) -> str:
        if self._clock is None:
            from datetime import UTC

            value = datetime.now(UTC)
        else:
            value = self._clock()
        try:
            return _canonical_utc_timestamp(value, "repository clock")
        except (TypeError, ValueError) as exc:
            raise ContractViolation(
                "repository clock must return a timezone-aware datetime"
            ) from exc

    def _append_audit(
        self,
        connection: sqlite3.Connection,
        head: AuditHead,
        *,
        object_ref: ArtifactRef,
        before_sha256: str,
        after_sha256: str,
    ) -> AuditEntry:
        entry = AuditEntryDraft(
            run_id=head.run_id,
            sequence=head.sequence + 1,
            actor=AuditActorRole.SYSTEM.value,
            action=AuditAction.CASE_STATE_CHANGED,
            object_ref=object_ref,
            before_sha256=before_sha256,
            after_sha256=after_sha256,
            manifest_id=head.manifest_id,
            recorded_at=self._recorded_at(),
            prev_entry_hash=head.entry_hash,
        ).seal()
        entry_json, entry_sha256 = _document(entry)
        connection.execute(
            """
            INSERT INTO audit_entries(
                run_id, sequence, manifest_id, actor, action,
                object_kind, object_id, before_sha256, after_sha256,
                recorded_at, prev_entry_hash, entry_hash,
                entry_json, document_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entry.run_id,
                entry.sequence,
                entry.manifest_id,
                entry.actor,
                entry.action.value,
                entry.object_ref.kind.value,
                entry.object_ref.artifact_id,
                entry.before_sha256,
                entry.after_sha256,
                entry.recorded_at,
                entry.prev_entry_hash,
                entry.entry_hash,
                entry_json,
                entry_sha256,
            ),
        )
        cursor = connection.execute(
            """
            UPDATE runs
            SET revision = ?, audit_head_sequence = ?, audit_head_hash = ?
            WHERE run_id = ? AND revision = ?
              AND audit_head_sequence = ? AND audit_head_hash = ?
            """,
            (
                head.run_revision + 1,
                entry.sequence,
                entry.entry_hash,
                head.run_id,
                head.run_revision,
                head.sequence,
                head.entry_hash,
            ),
        )
        if cursor.rowcount != 1:
            raise ConcurrentModification("run audit head changed during M3 transaction")
        return entry

    def _commit_case_version(
        self,
        connection: sqlite3.Connection,
        *,
        previous: CaseSnapshot,
        new_case: Case,
        expected_head: AuditHead,
        object_ref: ArtifactRef,
    ) -> CaseSnapshot:
        previous_json, previous_sha256 = _document(previous.case)
        del previous_json
        case_json, case_sha256 = _document(new_case)
        audit = self._append_audit(
            connection,
            expected_head,
            object_ref=object_ref,
            before_sha256=previous_sha256,
            after_sha256=case_sha256,
        )
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
        if cursor.rowcount != 1:
            raise ConcurrentModification("case revision changed during M3 transaction")
        return CaseSnapshot(case=new_case, revision=new_revision)

    @staticmethod
    def _validate_verdict_review_binding(
        run_id: str,
        verdict: Verdict,
        review: ProceduralReview,
    ) -> None:
        if (
            verdict.run_id != run_id
            or review.run_id != run_id
            or review.case_id != verdict.case_id
            or review.evidence_pack_id != verdict.evidence_pack_id
            or review.evidence_pack_version != verdict.evidence_pack_version
            or review.reviewed_verdict_id != verdict.verdict_id
            or review.reviewed_verdict_version != verdict.version
            or review.reviewed_verdict_sha256 != verdict.verdict_sha256
            or review.manifest_id != verdict.manifest_id
        ):
            raise ContractViolation("procedural review does not bind the supplied verdict")
